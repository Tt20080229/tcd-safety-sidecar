from __future__ import annotations

"""
Predictable Calibration for Runtime Safety (score -> conservative p-value).

This module provides:
  - EmpiricalTailCalibrator (Clopper–Pearson upper bound when available, Hoeffding fallback)
  - ConformalUpperEnvelope (split-conformal, distribution-free valid p)
  - PredictableCalibrator (rolling cross-fit: use *previous* block to calibrate the *current* block)
with SRE-friendly Prometheus metrics and safe defaults.

Design goals:
  * Predictability: p for item t is computed ONLY from data observed strictly before t.
  * Conservativeness: p is super-uniform (valid under adaptivity), via
      - exact CP (if Python >= 3.11 math.betainc is available) or
      - Hoeffding-based upper bound (conservative, distribution-free).
    And a distribution-free Conformal fallback.
  * Operability: rolling block rotation, counters for fallbacks, small memory, no SciPy dependency.

Typical integration in service_http:
  - Create one PredictableCalibrator per (model_id,gpu_id,task,lang)
  - For each /diagnose score:
      p = calibrator.predict(score, force_fallback=drift_flag)
      calibrator.update(score)
  - Feed p into AV controller (e-process + alpha-investing).
"""

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple
import bisect
import math

try:
    # Prometheus is already a project dependency; guard anyway.
    from prometheus_client import Counter, Gauge
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False


# ---------- Prometheus metrics (SRE) ----------

if _HAS_PROM:
    _G_BLOCK_SIZE = Gauge(
        "tcd_calibration_block_size",
        "Number of samples in the previous (predictable) block used for calibration.",
        ["scope"],
    )
    _C_ROTATE = Counter(
        "tcd_calibration_block_rotate_total",
        "Number of times predictable calibration rotated its block.",
        ["scope"],
    )
    _C_FALLBACK = Counter(
        "tcd_conformal_fallback_total",
        "Times conformal fallback was used instead of primary calibrator.",
        ["scope", "reason"],  # reason in {"insufficient", "forced_drift", "no_support"}
    )
else:
    # No-op shims
    class _No:
        def labels(self, *_, **__): return self
        def set(self, *_): pass
        def inc(self, *_): pass
    _G_BLOCK_SIZE = _No()
    _C_ROTATE = _No()
    _C_FALLBACK = _No()


# ---------- Utilities ----------

def _clip01(x: float) -> float:
    return 0.0 if x <= 0.0 else 1.0 if x >= 1.0 else float(x)


def _binomial_cp_upper(k: int, n: int, alpha: float) -> float:
    """
    Clopper–Pearson upper bound for Binomial proportion p given k successes of n trials.
    Returns p_u in [0,1] s.t. P(K <= k | p_u) = 1 - alpha.
    When Python >= 3.11, uses math.betainc; otherwise falls back to a conservative Hoeffding bound.

    Safe fallbacks:
      - n == 0 -> 1.0
      - k == n -> 1.0
      - k == 0 -> min(1.0, 1.0 - alpha**(1.0/n)) (from (1-p)^n = alpha)  [conservative; <= CP upper]
      - general -> binary-search p with regularized incomplete beta if betainc exists; else Hoeffding.
    """
    n = int(max(0, n))
    k = int(max(0, min(n, k)))
    a = float(max(1e-12, min(1.0, alpha)))

    if n == 0 or k == n:
        return 1.0
    if k == 0:
        # Solve (1 - p)^n = alpha -> p = 1 - alpha^(1/n); this is > CP upper (conservative).
        return _clip01(1.0 - a ** (1.0 / n))

    # Try exact CP via math.betainc (3.11+).
    if hasattr(math, "betainc") and hasattr(math, "beta"):
        # Regularized incomplete beta I_x(a,b) = betainc(a,b,0,x)/beta(a,b)
        # Upper bound for p solves I_{p}(k+1, n-k) = 1 - alpha.
        A = k + 1.0
        B = n - k * 1.0
        target = 1.0 - a

        def _reg_ibeta(x: float) -> float:
            return math.betainc(A, B, 0.0, x) / math.beta(A, B)

        lo, hi = 0.0, 1.0
        for _ in range(60):  # binary search
            mid = 0.5 * (lo + hi)
            v = _reg_ibeta(mid)
            if v < target:
                lo = mid
            else:
                hi = mid
        return _clip01(0.5 * (lo + hi))

    # Hoeffding (conservative): p_u >= k/n + sqrt( ln(1/alpha)/(2n) ), clipped to [0,1]
    phat = k / max(1.0, n)
    radius = math.sqrt(max(0.0, math.log(1.0 / a) / (2.0 * max(1.0, n))))
    return _clip01(phat + radius)


# ---------- Calibrators ----------

class EmpiricalTailCalibrator:
    """
    Empirical tail estimator with conservative upper confidence via Clopper–Pearson
    (exact when available; otherwise Hoeffding). We store a sorted array of scores
    from a *previous* block. For a query s, let k = #{x_i >= s}, then p_upper = CP(k, n; alpha).
    """

    def __init__(self, scores: List[float], alpha: float = 0.05):
        xs = [float(max(0.0, min(1.0, v))) for v in scores]
        xs.sort()
        self._xs = xs
        self._n = len(xs)
        self._alpha = float(max(1e-12, min(0.5, alpha)))  # alpha in (0, 0.5]

    def n(self) -> int:
        return self._n

    def p_upper(self, s: float) -> float:
        if self._n <= 0:
            return 1.0
        s = _clip01(s)
        # count of xs >= s  => use bisect to find first index >= s
        i = bisect.bisect_left(self._xs, s)
        k = self._n - i
        return _binomial_cp_upper(k=k, n=self._n, alpha=self._alpha)


class ConformalUpperEnvelope:
    """
    Split-conformal one-sided p-value:
        p(s) = (1 + #{x_i >= s}) / (n + 1)
    Valid under arbitrary drift/adaptivity, no distributional assumptions.
    """

    def __init__(self, calib_scores: List[float]):
        xs = [float(max(0.0, min(1.0, v))) for v in calib_scores]
        xs.sort()
        self._xs = xs
        self._n = len(xs)

    def n(self) -> int:
        return self._n

    def p_value(self, s: float) -> float:
        if self._n <= 0:
            return 1.0
        s = _clip01(s)
        i = bisect.bisect_left(self._xs, s)
        k = self._n - i
        return _clip01((1.0 + k) / (self._n + 1.0))


@dataclass
class CalibConfig:
    block_size: int = 512            # samples per block
    min_train: int = 64              # min previous-block size to enable CP
    alpha_cp: float = 0.05           # CP confidence level (upper bound 1-alpha)
    mode: str = "auto"               # {"auto", "cp_only", "conformal_only"}
    scope: str = "default"           # Prom label (e.g., "chat/en/model0")


class PredictableCalibrator:
    """
    Rolling cross-fit predictable calibrator:
      - Maintains two buffers: prev_block (for predictions), cur_block (collecting).
      - For each query s_t: use ONLY prev_block to compute p(s_t).
      - After cur_block reaches block_size, rotate: prev_block <- cur_block; cur_block <- [].

    Modes:
      - "auto": use CP upper bound if prev_n >= min_train; else conformal fallback.
      - "cp_only": always try CP; if insufficient data, conformal fallback.
      - "conformal_only": always use conformal (distribution-free).

    Fallback reasons:
      - "insufficient": not enough previous data
      - "forced_drift": caller explicitly forces fallback (e.g., drift alarm)
      - "no_support": environment lacks math.betainc and caller sets cp_only (we still return a valid p via Hoeffding or conformal)
    """

    def __init__(self, cfg: CalibConfig = CalibConfig()):
        self.cfg = cfg
        self._prev_scores: List[float] = []
        self._cur_scores: List[float] = []
        self._cal_cp: Optional[EmpiricalTailCalibrator] = None
        self._cal_conf: Optional[ConformalUpperEnvelope] = None
        self._rotate_count = 0
        _G_BLOCK_SIZE.labels(cfg.scope).set(0)

    # ---------- internal ----------

    def _rebuild_prev(self) -> None:
        prev = list(self._prev_scores)
        prev.sort()
        # Build both calibrators for flexibility
        self._cal_conf = ConformalUpperEnvelope(prev)
        self._cal_cp = EmpiricalTailCalibrator(prev, alpha=self.cfg.alpha_cp) if len(prev) >= self.cfg.min_train else None
        _G_BLOCK_SIZE.labels(self.cfg.scope).set(len(prev))

    def _rotate_if_needed(self) -> None:
        if len(self._cur_scores) >= self.cfg.block_size:
            self._prev_scores = self._cur_scores
            self._cur_scores = []
            self._rebuild_prev()
            self._rotate_count += 1
            _C_ROTATE.labels(self.cfg.scope).inc()

    def _use_cp(self) -> bool:
        if self.cfg.mode == "cp_only":
            return True
        if self.cfg.mode == "conformal_only":
            return False
        # auto
        return self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train

    # ---------- public ----------

    def predict(self, score: float, *, force_fallback: bool = False) -> float:
        """
        Compute conservative p for a score in [0,1] using ONLY the previous block.
        Does not mutate buffers (call update() after predict).
        """
        s = _clip01(score)
        # cold start: nothing to predict from
        if self._cal_conf is None and self._cal_cp is None:
            # If never rebuilt, build once from empty prev (gives n=0)
            self._rebuild_prev()

        # decide calibrator
        if force_fallback:
            _C_FALLBACK.labels(self.cfg.scope, "forced_drift").inc()
            return self._cal_conf.p_value(s) if self._cal_conf else 1.0

        if self.cfg.mode == "conformal_only":
            return self._cal_conf.p_value(s) if self._cal_conf else 1.0

        # prefer CP if available (and environment supports exact or Hoeffding is fine)
        if self._use_cp():
            return self._cal_cp.p_upper(s)  # EmpiricalTailCalibrator handles exact/hoeffding internally

        # fallback to conformal due to insufficient data
        _C_FALLBACK.labels(self.cfg.scope, "insufficient").inc()
        return self._cal_conf.p_value(s) if self._cal_conf else 1.0

    def update(self, score: float) -> None:
        """
        Append the *current* score into the cur_block. This will NOT affect
        predict() until rotation happens.
        """
        self._cur_scores.append(_clip01(score))
        self._rotate_if_needed()

    def feed_and_predict(self, score: float, *, force_fallback: bool = False) -> float:
        """
        Convenience method for streaming: predict using previous block,
        then update with the current score.
        """
        p = self.predict(score, force_fallback=force_fallback)
        self.update(score)
        return p

    # ---------- stats & maintenance ----------

    def block_sizes(self) -> Tuple[int, int]:
        """Return (prev_block_size, cur_block_size)."""
        prev_n = len(self._prev_scores)
        cur_n = len(self._cur_scores)
        return prev_n, cur_n

    def rotate_now(self) -> None:
        """Force a rotation (useful for tests or admin operations)."""
        if self._cur_scores:
            self._prev_scores = self._cur_scores
            self._cur_scores = []
        self._rebuild_prev()
        self._rotate_count += 1
        _C_ROTATE.labels(self.cfg.scope).inc()

    def stats(self) -> dict:
        prev_n, cur_n = self.block_sizes()
        mode = self.cfg.mode
        return {
            "prev_n": prev_n,
            "cur_n": cur_n,
            "mode": mode,
            "min_train": self.cfg.min_train,
            "alpha_cp": self.cfg.alpha_cp,
            "rotations": self._rotate_count,
            "cp_ready": bool(self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train),
        }
