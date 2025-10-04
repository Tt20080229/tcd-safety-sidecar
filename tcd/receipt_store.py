from __future__ import annotations

"""
Receipt stores — pluggable persistence for verifiable receipts with chain integrity checks.

Goals
  - Persist attested receipts (head/body/signature/public key) with minimal overhead.
  - Provide chain continuity checks (prev pointer linearity) and basic audit stats.
  - Offer multiple backends with the same API: in-memory, JSONL (append-only), SQLite.
  - Be SRE-friendly: safe appends (fsync), rotation hooks, Prom/OTel metric surfaces.

Design notes
  - Interface: ReceiptStore (append/get/last_head/verify_chain_window/stats).
  - JSONL backend is the default for simplicity and portability; SQLite is optional.
  - All backends are thread-safe (RLock). These stores are process-local; for
    cross-process deployments, mount a shared volume or use the SQLite backend.
  - We do not index by tenant by default (to avoid accidental deanonymization).
    If multi-tenant partitioning is required, run separate store instances per tenant
    or put a tenant-hash prefix in the JSONL path.

Security & privacy
  - We persist only the attested canonical body and the head (and optional signature + key).
  - No raw prompts/outputs should be present in `receipt_body_json` (by design of issuer);
    operators are responsible for keeping that contract.
"""

import dataclasses
import io
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Protocol

from .exporter import TCDPrometheusExporter
from .verify import verify_chain


@dataclasses.dataclass(frozen=True)
class ReceiptRow:
    """
    A single persisted receipt entry.

    id: monotonically increasing integer (per backend instance).
    head_hex: the computed receipt head (domain-separated BLAKE3).
    body_json: canonical JSON string (the "receipt_body" from issuer).
    sig_hex: optional Ed25519 signature hex string (may be empty).
    verify_key_hex: optional Ed25519 verify key hex string (may be empty).
    ts: storage timestamp (seconds since epoch, float).
    """
    id: int
    head_hex: str
    body_json: str
    sig_hex: str
    verify_key_hex: str
    ts: float


class ReceiptStore(Protocol):
    """Minimal contract every store backend must satisfy."""

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        """Append a receipt, returns assigned id."""
        ...

    def get(self, rid: int) -> Optional[ReceiptRow]:
        """Fetch a receipt by id (None if not found)."""
        ...

    def tail(self, n: int) -> List[ReceiptRow]:
        """Return the last n receipts (ascending by id)."""
        ...

    def last_head(self) -> Optional[str]:
        """Return the last (most recent) head or None."""
        ...

    def count(self) -> int:
        """Number of receipts stored."""
        ...

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        """
        Verify linear chain for the last `window` receipts.
        Uses verify_chain(heads, bodies) to assert prev pointers and body/head binding.
        """
        ...

    def stats(self) -> Dict[str, float]:
        """Basic SRE stats: count, size_bytes (if applicable), last_ts, append_qps estimate."""
        ...


# =============================================================================
# In-memory backend
# =============================================================================


class InMemoryReceiptStore(ReceiptStore):
    """Process-local in-memory store (good for tests)."""

    def __init__(self, prom: Optional[TCDPrometheusExporter] = None):
        self._rows: List[ReceiptRow] = []
        self._id = 0
        self._lk = threading.RLock()
        self._prom = prom
        self._append_ema = 0.0
        self._ema_alpha = 0.1

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        ts = time.time()
        with self._lk:
            self._id += 1
            rid = self._id
            row = ReceiptRow(rid, head_hex, body_json, sig_hex or "", verify_key_hex or "", ts)
            self._rows.append(row)
            # qps ema
            self._append_ema = (1 - self._ema_alpha) * self._append_ema + self._ema_alpha * 1.0
        if self._prom:
            self._prom.observe_latency(0.0)  # placeholder to keep metric surfaced
        return rid

    def get(self, rid: int) -> Optional[ReceiptRow]:
        with self._lk:
            idx = rid - 1
            if 0 <= idx < len(self._rows):
                return self._rows[idx]
            return None

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            return list(self._rows[-max(0, n):])

    def last_head(self) -> Optional[str]:
        with self._lk:
            return self._rows[-1].head_hex if self._rows else None

    def count(self) -> int:
        with self._lk:
            return len(self._rows)

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        with self._lk:
            rows = self._rows[-max(0, window):]
            if not rows:
                return True
            heads = [r.head_hex for r in rows]
            bodies = [r.body_json for r in rows]
        return bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))

    def stats(self) -> Dict[str, float]:
        with self._lk:
            last_ts = self._rows[-1].ts if self._rows else 0.0
            return {"count": float(len(self._rows)), "size_bytes": 0.0, "last_ts": float(last_ts), "append_qps_ema": float(self._append_ema)}


# =============================================================================
# JSONL backend (append-only)
# =============================================================================


class JsonlReceiptStore(ReceiptStore):
    """
    Append-only JSONL store with fsync for durability.

    File format: one object per line
      {"id": int, "ts": float, "receipt": "<head_hex>", "receipt_body": "<canonical body json>",
       "receipt_sig": "<sig hex or empty>", "verify_key": "<vk hex or empty>"}

    Rotation (manual): create a new store instance pointing to a new path; the old file remains as archive.
    """

    def __init__(self, path: str, prom: Optional[TCDPrometheusExporter] = None, *, create_dirs: bool = True, fsync_writes: bool = True):
        self._path = Path(path)
        if create_dirs:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lk = threading.RLock()
        self._prom = prom
        self._fsync = bool(fsync_writes)
        self._next_id = 1
        self._last_head: Optional[str] = None
        self._append_ema = 0.0
        self._ema_alpha = 0.1

        # Initialize next_id from file contents, without loading entire file into memory
        if self._path.exists():
            try:
                with self._path.open("r", encoding="utf-8") as fr:
                    last_line = ""
                    for line in fr:
                        if line.strip():
                            last_line = line
                    if last_line:
                        obj = json.loads(last_line)
                        self._next_id = int(obj.get("id", 0)) + 1
                        self._last_head = str(obj.get("receipt", "")) or None
            except Exception:
                # If file is corrupted, continue with a conservative fallback (append from next id)
                pass

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        ts = time.time()
        with self._lk:
            rid = self._next_id
            self._next_id += 1

            obj = {
                "id": rid,
                "ts": ts,
                "receipt": head_hex,
                "receipt_body": body_json,
                "receipt_sig": sig_hex or "",
                "verify_key": verify_key_hex or "",
            }
            data = json.dumps(obj, ensure_ascii=False) + "\n"

            # atomic-ish append
            with self._path.open("a", encoding="utf-8") as fw:
                fw.write(data)
                fw.flush()
                if self._fsync:
                    os.fsync(fw.fileno())

            self._last_head = head_hex
            self._append_ema = (1 - self._ema_alpha) * self._append_ema + self._ema_alpha * 1.0

        if self._prom:
            # Hook point for a histogram like tcd_receipt_size_bytes; we reuse observe_latency to surface
            self._prom.observe_latency(0.0)
        return rid

    def _iter_tail(self, n: int) -> List[ReceiptRow]:
        # Efficient tail read without loading whole file: read blocks from end.
        if not self._path.exists() or n <= 0:
            return []

        rows: List[ReceiptRow] = []
        # Simple approach: read entire file if small; otherwise do a two-pass tail (acceptable for tests/demo).
        try:
            size = self._path.stat().st_size
            if size < 4 * 1024 * 1024:
                lines = self._path.read_text(encoding="utf-8").splitlines()
                for s in lines[-n:]:
                    obj = json.loads(s)
                    rows.append(
                        ReceiptRow(
                            id=int(obj["id"]),
                            head_hex=str(obj["receipt"]),
                            body_json=str(obj["receipt_body"]),
                            sig_hex=str(obj.get("receipt_sig", "")),
                            verify_key_hex=str(obj.get("verify_key", "")),
                            ts=float(obj["ts"]),
                        )
                    )
                return rows
        except Exception:
            # Fallback to slow path
            pass

        # Slow path: iterate forward (still streaming), keep last n
        try:
            dq: List[str] = []
            with self._path.open("r", encoding="utf-8") as fr:
                for line in fr:
                    if not line.strip():
                        continue
                    dq.append(line)
                    if len(dq) > n:
                        dq.pop(0)
            for s in dq:
                obj = json.loads(s)
                rows.append(
                    ReceiptRow(
                        id=int(obj["id"]),
                        head_hex=str(obj["receipt"]),
                        body_json=str(obj["receipt_body"]),
                        sig_hex=str(obj.get("receipt_sig", "")),
                        verify_key_hex=str(obj.get("verify_key", "")),
                        ts=float(obj["ts"]),
                    )
                )
        except Exception:
            return []
        return rows

    def get(self, rid: int) -> Optional[ReceiptRow]:
        if rid <= 0:
            return None
        # Scan; for JSONL this is O(n). Intended for tests/operator usage.
        try:
            with self._path.open("r", encoding="utf-8") as fr:
                for line in fr:
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    if int(obj.get("id", -1)) == rid:
                        return ReceiptRow(
                            id=int(obj["id"]),
                            head_hex=str(obj["receipt"]),
                            body_json=str(obj["receipt_body"]),
                            sig_hex=str(obj.get("receipt_sig", "")),
                            verify_key_hex=str(obj.get("verify_key", "")),
                            ts=float(obj["ts"]),
                        )
        except Exception:
            return None
        return None

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            return self._iter_tail(max(0, int(n)))

    def last_head(self) -> Optional[str]:
        with self._lk:
            return self._last_head

    def count(self) -> int:
        # Count lines; for large files this is O(n). For production, prefer SQLite.
        try:
            c = 0
            with self._path.open("r", encoding="utf-8") as fr:
                for _ in fr:
                    c += 1
            return c
        except Exception:
            return 0

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        rows = self.tail(window)
        if not rows:
            return True
        heads = [r.head_hex for r in rows]
        bodies = [r.body_json for r in rows]
        return bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))

    def stats(self) -> Dict[str, float]:
        size = 0.0
        last_ts = 0.0
        try:
            st = self._path.stat()
            size = float(st.st_size)
        except Exception:
            pass
        tail1 = self.tail(1)
        if tail1:
            last_ts = float(tail1[-1].ts)
        return {
            "count": float(self.count()),
            "size_bytes": size,
            "last_ts": last_ts,
            "append_qps_ema": float(self._append_ema),
        }


# =============================================================================
# SQLite backend (optional; stdlib only)
# =============================================================================


_SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    head TEXT NOT NULL,
    body TEXT NOT NULL,
    sig TEXT,
    vk TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_ts ON receipts(ts);
"""


class SqliteReceiptStore(ReceiptStore):
    """
    SQLite-backed store with indexes. Suitable for multi-process access on the same host
    (subject to SQLite locking semantics); for highly concurrent usage, consider a proper
    DB. Uses WAL and synchronous=NORMAL by default for decent durability/perf tradeoff.
    """

    def __init__(self, path: str, prom: Optional[TCDPrometheusExporter] = None):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lk = threading.RLock()
        self._prom = prom
        self._conn = sqlite3.connect(str(self._path), timeout=30.0, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(_SQL_SCHEMA)

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        ts = time.time()
        with self._lk:
            cur = self._conn.cursor()
            cur.execute(
                "INSERT INTO receipts (ts, head, body, sig, vk) VALUES (?, ?, ?, ?, ?)",
                (ts, head_hex, body_json, sig_hex or "", verify_key_hex or ""),
            )
            rid = int(cur.lastrowid)
            cur.close()
        if self._prom:
            self._prom.observe_latency(0.0)
        return rid

    def get(self, rid: int) -> Optional[ReceiptRow]:
        with self._lk:
            cur = self._conn.cursor()
            cur.execute("SELECT id, ts, head, body, sig, vk FROM receipts WHERE id=?", (int(rid),))
            row = cur.fetchone()
            cur.close()
        if not row:
            return None
        rid, ts, head, body, sig, vk = row
        return ReceiptRow(int(rid), str(head), str(body), str(sig or ""), str(vk or ""), float(ts))

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            cur = self._conn.cursor()
            cur.execute("SELECT id, ts, head, body, sig, vk FROM receipts ORDER BY id DESC LIMIT ?", (int(max(0, n)),))
            rows = cur.fetchall()
            cur.close()
        out: List[ReceiptRow] = []
        for rid, ts, head, body, sig, vk in reversed(rows):
            out.append(ReceiptRow(int(rid), str(head), str(body), str(sig or ""), str(vk or ""), float(ts)))
        return out

    def last_head(self) -> Optional[str]:
        with self._lk:
            cur = self._conn.cursor()
            cur.execute("SELECT head FROM receipts ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            cur.close()
        return str(row[0]) if row else None

    def count(self) -> int:
        with self._lk:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM receipts")
            c = cur.fetchone()[0]
            cur.close()
        return int(c)

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        rows = self.tail(window)
        if not rows:
            return True
        heads = [r.head_hex for r in rows]
        bodies = [r.body_json for r in rows]
        return bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))

    def stats(self) -> Dict[str, float]:
        last_ts = 0.0
        tail1 = self.tail(1)
        if tail1:
            last_ts = float(tail1[-1].ts)
        size_bytes = 0.0
        try:
            size_bytes = float(self._path.stat().st_size)
        except Exception:
            pass
        return {"count": float(self.count()), "size_bytes": size_bytes, "last_ts": last_ts}


# =============================================================================
# Factory & helpers
# =============================================================================


def build_store_from_env(prom: Optional[TCDPrometheusExporter] = None) -> ReceiptStore:
    """
    Construct a store backend using environment knobs:

      TCD_RECEIPT_STORE = "jsonl" | "sqlite" | "memory"   (default: "jsonl")
      TCD_RECEIPT_PATH  = path to file (jsonl or sqlite). default: "./data/receipts.jsonl"
      TCD_RECEIPT_FSYNC = "1" | "0" for JSONL fsync writes (default: "1")

    For SQLite, path should end with ".db" (by convention).
    """
    backend = (os.environ.get("TCD_RECEIPT_STORE") or "jsonl").strip().lower()
    path = os.environ.get("TCD_RECEIPT_PATH") or "./data/receipts.jsonl"

    if backend == "memory":
        return InMemoryReceiptStore(prom=prom)
    if backend == "sqlite":
        # If a jsonl-looking path is provided, map to a .db file in the same directory.
        p = Path(path)
        if p.suffix.lower() != ".db":
            path = str(p.with_suffix(".db"))
        return SqliteReceiptStore(path=path, prom=prom)
    # default: jsonl
    fsync = (os.environ.get("TCD_RECEIPT_FSYNC", "1").strip() == "1")
    return JsonlReceiptStore(path=path, prom=prom, fsync_writes=fsync)


def verify_recent_chain(store: ReceiptStore, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
    """
    Convenience wrapper for periodic SRE audits. Intended to be called by a background job
    (e.g., cron, k8s CronJob, or a /admin/health endpoint). Returns True if chain is valid.
    """
    try:
        return store.verify_chain_window(window, label_salt_hex=label_salt_hex)
    except Exception:
        return False
