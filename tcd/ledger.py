# FILE: tcd/ledger.py
from __future__ import annotations

"""
TCD Ledger — Wealth (alpha-investing) persistence + Receipt chain storage.

Why this module:
  - Cross-instance consistency for alpha-investing wealth and spending events
  - Idempotent writes to avoid double-spend under retries
  - Durable receipt chain (head/body/sig/prev) with integrity helpers
  - Minimal deps; production-ready SQLite backend with WAL + safe schema

Interfaces:
  - SubjectKey: logical subject (tenant, user, session)
  - WealthRecord: current wealth snapshot + policy metadata
  - Ledger (ABC): ensure/get/update wealth; idempotent event apply; receipt store/query
  - InMemoryLedger: fast, tests/smoke
  - SQLiteLedger: durable, atomic, WAL; single-file DB

Notes:
  - We DO NOT compute decisions here; only persist results emitted by controllers.
  - Idempotency is per event_id (your /diagnose caller should pass request_id/idempotency-key).
  - High-cardinality Prom labels must be guarded by your exporter; we keep internal counters lightweight.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Optional, Tuple, List
import json
import os
import sqlite3
import threading
import time
import hmac
import hashlib


# ---------- Data Models ----------

@dataclass(frozen=True)
class SubjectKey:
    tenant: str
    user: str
    session: str

    def as_tuple(self) -> Tuple[str, str, str]:
        return (self.tenant, self.user, self.session)

    def as_str(self) -> str:
        # canonical stable key used in DB; avoids json for hot paths
        return f"{self.tenant}::{self.user}::{self.session}"


@dataclass
class WealthRecord:
    subject: SubjectKey
    wealth: float
    alpha0: float
    hard_floor: float
    policy_ref: str
    version: int
    updated_ts: float
    meta: Dict[str, object]


@dataclass
class EventApplyResult:
    applied: bool          # True if new event applied, False if duplicate (idempotent hit)
    wealth_after: float
    alpha_spent: float     # what caller says was spent (informational echo)
    updated_ts: float


@dataclass
class ReceiptRecord:
    head: str
    body: str
    sig: str
    prev: Optional[str]
    ts: float


# ---------- Exceptions ----------

class LedgerError(RuntimeError):
    pass


# ---------- Base Interface ----------

class Ledger:
    """
    Abstract ledger API.
    """

    # Wealth / Investing

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        """
        Ensure subject exists, without mutating wealth if already present.
        Returns the current WealthRecord.
        """
        raise NotImplementedError

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        """Return wealth snapshot or None if subject not found."""
        raise NotImplementedError

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        """
        Idempotent wealth update per decision:
          wealth <- max(hard_floor, wealth - alpha_spent + reward)

        If event_id already exists, returns applied=False and does NOT change wealth.
        """
        raise NotImplementedError

    # Receipts

    def append_receipt(self, rec: ReceiptRecord) -> None:
        """
        Store a receipt; assumes rec.prev matches current chain head (caller ensures).
        This keeps storage decoupled from integrity (verified by tcd.verify utilities).
        """
        raise NotImplementedError

    def chain_head(self) -> Optional[str]:
        """Return the head hex of the latest stored receipt."""
        raise NotImplementedError

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        """Return last N receipts ordered by ts ascending (oldest first)."""
        raise NotImplementedError


# ---------- In-Memory Implementation (tests / dev) ----------

class InMemoryLedger(Ledger):
    def __init__(self):
        self._w: Dict[str, WealthRecord] = {}
        self._events: Dict[str, str] = {}  # event_id -> subject_str (for idempotency)
        self._receipts: List[ReceiptRecord] = []
        self._lock = threading.RLock()

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        now = time.time()
        s = subject.as_str()
        with self._lock:
            wr = self._w.get(s)
            if wr is None:
                wr = WealthRecord(
                    subject=subject,
                    wealth=float(alpha0),
                    alpha0=float(alpha0),
                    hard_floor=float(hard_floor),
                    policy_ref=str(policy_ref),
                    version=1,
                    updated_ts=now,
                    meta=dict(meta or {}),
                )
                self._w[s] = wr
            return wr

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        with self._lock:
            return self._w.get(subject.as_str())

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        now = time.time()
        s = subject.as_str()
        with self._lock:
            if event_id in self._events:
                # Idempotent hit — no change
                wr = self._w.get(s)
                wealth_after = float(wr.wealth) if wr else 0.0
                return EventApplyResult(False, wealth_after, float(alpha_spent), now)

            wr = self._w.get(s)
            if wr is None:
                raise LedgerError("apply_event: subject not found; call ensure_subject first")

            # wealth update: hard floor guard
            wealth_after = max(float(wr.hard_floor), float(wr.wealth) - float(alpha_spent) + float(reward))
            wr.wealth = wealth_after
            wr.updated_ts = now
            wr.policy_ref = str(policy_ref)
            wr.version += 1
            if meta:
                wr.meta.update(dict(meta))

            self._events[event_id] = s
            return EventApplyResult(True, wealth_after, float(alpha_spent), now)

    def append_receipt(self, rec: ReceiptRecord) -> None:
        with self._lock:
            # simple linear chain: require prev equals last head (or None if empty)
            prev = self._receipts[-1].head if self._receipts else None
            if prev != rec.prev:
                # don't throw — keep storage decoupled; but raise to surface inconsistency early in dev/tests
                raise LedgerError("append_receipt: chain prev pointer mismatch")
            self._receipts.append(rec)

    def chain_head(self) -> Optional[str]:
        with self._lock:
            return self._receipts[-1].head if self._receipts else None

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        with self._lock:
            return list(self._receipts[-limit:]) if limit > 0 else list(self._receipts)


# ---------- SQLite Implementation (production) ----------

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS subjects (
  skey            TEXT PRIMARY KEY,              -- "tenant::user::session"
  tenant          TEXT NOT NULL,
  usr             TEXT NOT NULL,
  sess            TEXT NOT NULL,
  wealth          REAL NOT NULL,
  alpha0          REAL NOT NULL,
  hard_floor      REAL NOT NULL,
  policy_ref      TEXT NOT NULL,
  version         INTEGER NOT NULL,
  updated_ts      REAL NOT NULL,
  meta_json       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  event_id        TEXT PRIMARY KEY,
  skey            TEXT NOT NULL,
  alpha_spent     REAL NOT NULL,
  reward          REAL NOT NULL,
  policy_ref      TEXT NOT NULL,
  ts              REAL NOT NULL,
  meta_json       TEXT NOT NULL,
  FOREIGN KEY(skey) REFERENCES subjects(skey) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS receipts (
  head            TEXT PRIMARY KEY,
  body            TEXT NOT NULL,
  sig             TEXT,
  prev            TEXT,
  ts              REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_ts ON receipts(ts);
"""

class SQLiteLedger(Ledger):
    """
    Durable single-file ledger. Thread-safe via connection-per-thread and a coarse process lock
    around write transactions (sufficient for FastAPI worker concurrency in most deployments).
    """

    def __init__(self, path: str = None):
        # default path: $TCD_LEDGER_DB or local file "tcd_ledger.db"
        self._path = path or os.environ.get("TCD_LEDGER_DB", "tcd_ledger.db")
        self._lock = threading.RLock()
        self._conn = self._open()
        self._migrate()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30.0, isolation_level=None, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)

    # ----- helpers -----

    def _subject_row_to_wr(self, row) -> WealthRecord:
        # row order must match SELECT columns
        skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json = row
        return WealthRecord(
            subject=SubjectKey(tenant=tenant, user=usr, session=sess),
            wealth=float(wealth),
            alpha0=float(alpha0),
            hard_floor=float(hard_floor),
            policy_ref=str(policy_ref),
            version=int(version),
            updated_ts=float(updated_ts),
            meta=json.loads(meta_json) if meta_json else {},
        )

    def _get_subject_row(self, skey: str):
        cur = self._conn.execute(
            "SELECT skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json "
            "FROM subjects WHERE skey=?",
            (skey,),
        )
        return cur.fetchone()

    # ----- Ledger API -----

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        now = time.time()
        skey = subject.as_str()
        with self._lock:
            row = self._get_subject_row(skey)
            if row:
                return self._subject_row_to_wr(row)
            self._conn.execute(
                "INSERT OR IGNORE INTO subjects(skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    skey, subject.tenant, subject.user, subject.session,
                    float(alpha0), float(alpha0), float(hard_floor),
                    str(policy_ref), 1, now, json.dumps(dict(meta or {}), separators=(',', ':'), ensure_ascii=False),
                ),
            )
            row = self._get_subject_row(skey)
            return self._subject_row_to_wr(row)

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        row = self._get_subject_row(subject.as_str())
        return self._subject_row_to_wr(row) if row else None

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        """
        Atomic transaction:
          - INSERT event (idempotent via PK)
          - If inserted, UPDATE wealth with floor guard
          - Return post-state and applied flag
        """
        now = time.time()
        skey = subject.as_str()
        meta_json = json.dumps(dict(meta or {}), separators=(',', ':'), ensure_ascii=False)

        with self._lock:
            # ensure subject exists
            if not self._get_subject_row(skey):
                raise LedgerError("apply_event: subject not found; call ensure_subject first")

            try:
                self._conn.execute("BEGIN IMMEDIATE")
                # try insert event
                try:
                    self._conn.execute(
                        "INSERT INTO events(event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (event_id, skey, float(alpha_spent), float(reward), str(policy_ref), now, meta_json),
                    )
                    inserted = True
                except sqlite3.IntegrityError:
                    inserted = False

                # fetch current wealth/hard_floor
                row = self._get_subject_row(skey)
                wr = self._subject_row_to_wr(row)

                if inserted:
                    wealth_after = max(wr.hard_floor, wr.wealth - float(alpha_spent) + float(reward))
                    self._conn.execute(
                        "UPDATE subjects SET wealth=?, policy_ref=?, version=version+1, updated_ts=?, meta_json=? "
                        "WHERE skey=?",
                        (
                            float(wealth_after),
                            str(policy_ref),
                            now,
                            json.dumps(wr.meta if not meta else {**wr.meta, **dict(meta)}, separators=(',', ':'), ensure_ascii=False),
                            skey,
                        ),
                    )
                    self._conn.execute("COMMIT")
                    return EventApplyResult(True, float(wealth_after), float(alpha_spent), now)
                else:
                    # duplicate; keep wealth unchanged
                    self._conn.execute("ROLLBACK")
                    return EventApplyResult(False, float(wr.wealth), float(alpha_spent), now)

            except Exception as e:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise LedgerError(f"apply_event failed: {e}") from e

    def append_receipt(self, rec: ReceiptRecord) -> None:
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO receipts(head, body, sig, prev, ts) VALUES(?,?,?,?,?)",
                    (str(rec.head), str(rec.body), str(rec.sig or ""), rec.prev, float(rec.ts)),
                )
            except sqlite3.IntegrityError as e:
                # duplicate head -> ignore or raise based on policy; we raise to surface anomaly
                raise LedgerError(f"append_receipt duplicate head: {e}") from e

    def chain_head(self) -> Optional[str]:
        cur = self._conn.execute("SELECT head FROM receipts ORDER BY ts DESC LIMIT 1")
        row = cur.fetchone()
        return row[0] if row else None

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        cur = self._conn.execute(
            "SELECT head, body, sig, prev, ts FROM receipts ORDER BY ts ASC LIMIT ?",
            (int(max(1, limit)),),
        )
        out: List[ReceiptRecord] = []
        for head, body, sig, prev, ts in cur.fetchall():
            out.append(ReceiptRecord(head=head, body=body, sig=sig, prev=prev, ts=float(ts)))
        return out


# ---------- Helpers (optional) ----------

def stable_subject_hash(sk: SubjectKey, *, key: Optional[bytes] = None, out_hex: int = 16) -> str:
    """
    Stable, optional-HMAC hash for using subject as metric label / privacy-preserving id.
    """
    s = sk.as_str().encode("utf-8")
    if key:
        h = hmac.new(key, s, hashlib.blake2s).hexdigest()
    else:
        h = hashlib.blake2s(s).hexdigest()
    return h[:max(8, int(out_hex))]
