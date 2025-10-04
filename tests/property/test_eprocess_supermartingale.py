# FILE: tests/property/test_eprocess_supermartingale.py
# Property tests (Hypothesis): e-process supermartingale, p-superuniform, and receipt chain consistency.

from __future__ import annotations

import json
import math
from typing import Callable, Dict, Iterable, List, Tuple

import numpy as np
import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from tcd.eprocess import EProcess, EProcessConfig
from tcd.attest import Attestor
from tcd.verify import verify_chain


# --------------------------- Helpers ---------------------------

def simulate_eprocess(
    n_seq: int,
    n_steps: int,
    p_gen: Callable[[int, float], float],
    *,
    seed: int = 0,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """
    Simulate e-process over multiple sequences.

    Args:
        n_seq: number of independent sequences (replications)
        n_steps: steps per sequence
        p_gen: function step -> p-value in (0,1], may depend on previous E (provide last E as arg2)
        seed: RNG seed

    Returns:
        final_E: shape [n_seq] final E_T for each sequence
        sup_E:   shape [n_seq] sup_{t <= T} E_t
        all_p:   shape [n_seq, n_steps] the generated p-values
    """
    rng = np.random.default_rng(seed)
    final_E = np.zeros(n_seq, dtype=float)
    sup_E = np.zeros(n_seq, dtype=float)
    all_p = np.zeros((n_seq, n_steps), dtype=float)

    for s in range(n_seq):
        ep = EProcess(EProcessConfig())  # BetaPDF map (a=0.5, b=1.0) by default
        cur_E = 1.0
        cur_sup = 1.0
        for t in range(n_steps):
            # generator may depend on time and last E
            u = float(rng.uniform(0.0, 1.0))
            p = float(p_gen(t, cur_E))
            # If generator uses RNG internally, ignore u; otherwise use u for uniform case:
            if math.isnan(p):  # convention: NaN means "use provided uniform u"
                p = u
            p = max(1e-12, min(1.0, p))
            all_p[s, t] = p
            e_t = ep.step([p])  # updates ep.logE internally
            cur_E *= e_t
            cur_sup = max(cur_sup, math.exp(ep.logE))
        final_E[s] = math.exp(ep.logE)
        sup_E[s] = cur_sup
    return final_E, sup_E, all_p


def superuniform_check(p_samples: np.ndarray, eps: float = 0.03) -> None:
    """
    Empirical super-uniform check: for a grid of thresholds t,
    Pr(P <= t) <= t + eps.
    """
    grid = np.array([0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 0.8])
    n = p_samples.size
    p_sorted = np.sort(p_samples.reshape(-1))
    for t in grid:
        count = (p_sorted <= t).sum()
        frac = count / float(n)
        assert frac <= t + eps, f"violates super-uniform at t={t}: frac={frac:.4f} > t+eps={t+eps:.4f}"


# --------------------------- Strategies ---------------------------

st_steps = st.integers(min_value=25, max_value=120)
st_alpha = st.sampled_from([0.01, 0.02, 0.05])

# --------------------------- Tests ---------------------------

@settings(
    max_examples=6,  # aggregate load across examples; each example simulates many sequences
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(n_steps=st_steps, alpha=st_alpha)
def test_supermartingale_uniform_and_ville(n_steps: int, alpha: float):
    """
    Under i.i.d. Uniform(0,1) p-values:
      - E[ E_T ] ≈ 1
      - Ville's inequality: P( sup_t E_t >= 1/alpha ) <= alpha (empirical, with slack)
    """
    N = 200  # sequences per example; 6 examples → 1200 total
    threshold = 1.0 / float(alpha)

    # p_gen returns NaN to indicate "use external uniform u" (see simulate_eprocess)
    def iid_uniform(_t: int, _E: float) -> float:
        return float("nan")

    final_E, sup_E, all_p = simulate_eprocess(N, n_steps, iid_uniform, seed=42)

    # Supermartingale (mean ≤ 1) within sampling slack
    mean_E = float(np.mean(final_E))
    assert mean_E <= 1.10, f"mean(E_T) too large: {mean_E:.3f} (> 1.10)"

    # Ville bound (empirical): fraction exceeding threshold should be <= alpha × slack
    frac_cross = float(np.mean(sup_E >= threshold))
    assert frac_cross <= alpha * 1.6 + 0.005, f"Ville empirical fail: frac={frac_cross:.4f}, alpha={alpha}"

    # p-superuniform sanity for uniform case (tight)
    superuniform_check(all_p, eps=0.02)


@settings(
    max_examples=6,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(n_steps=st_steps, alpha=st_alpha)
def test_supermartingale_adaptive_peeking_but_superuniform(n_steps: int, alpha: float):
    """
    Adaptive peeking: generator observes E_{t-1} and *inflates* p-values when E grows,
    ensuring conditional super-uniformity (stochastically larger than Uniform).

    We check:
      - mean(E_T) ≤ 1.10
      - Ville empirical bound with slack
      - p-values remain empirically super-uniform
    """
    N = 200
    threshold = 1.0 / float(alpha)

    rng = np.random.default_rng(7)

    def adaptive_superuniform(_t: int, last_E: float) -> float:
        # Base uniform draw:
        u = float(rng.uniform(0.0, 1.0))
        # Inflate p when last_E is large (more conservative): enforce a floor in [0, 0.9]
        # floor increases with log(last_E), but capped to 0.7 to keep power non-zero.
        floor = max(0.0, min(0.7, 0.15 * math.log1p(max(0.0, last_E - 1.0)) + 0.0))
        return max(u, floor)  # stochastically larger than Uniform → super-uniform

    final_E, sup_E, all_p = simulate_eprocess(N, n_steps, adaptive_superuniform, seed=8)

    mean_E = float(np.mean(final_E))
    assert mean_E <= 1.10, f"mean(E_T) too large under adaptive-superuniform: {mean_E:.3f}"

    frac_cross = float(np.mean(sup_E >= threshold))
    assert frac_cross <= alpha * 1.8 + 0.007, f"Ville empirical fail (adaptive): frac={frac_cross:.4f}, alpha={alpha}"

    superuniform_check(all_p, eps=0.03)


@settings(
    max_examples=4,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
@given(
    n=st.integers(min_value=1, max_value=25),
    have_witness=st.booleans(),
)
def test_receipt_chain_consistency(n: int, have_witness: bool):
    """
    Issue a chain of n receipts via Attestor and verify:
      - verify_chain OK on intact sequence
      - fails after a body mutation or order swap
    """
    att = Attestor(hash_alg="blake3")  # no signing key needed for this test

    heads: List[str] = []
    bodies: List[str] = []

    for i in range(n):
        req = {"rid": i, "tenant": "t", "user": "u", "session": "s"}
        comp = {"route": "default", "temperature": 0.7}
        eobj = {"e": 1.0}

        if have_witness:
            # lightweight integer segments (already integer lists)
            trace = [i, i + 1, i + 2]
            spec = [i * 2]
            feat = [0, 1]
            witness = (trace, spec, feat)
        else:
            witness = ([0], [0], [0])

        rcpt = att.issue(
            req_obj=req,
            comp_obj=comp,
            e_obj=eobj,
            witness_segments=witness,
            witness_tags=("trace", "spectrum", "feat"),
            meta={"i": i},
        )
        heads.append(rcpt["receipt"])
        bodies.append(rcpt["receipt_body"])

    assert verify_chain(heads, bodies), "verify_chain should succeed for intact chain"

    # Mutate a body (JSON) → should fail
    if n >= 1:
        bad_bodies = bodies.copy()
        body0 = json.loads(bad_bodies[0])
        body0["label_salt_version"] = int(body0.get("label_salt_version", 1)) + 1
        bad_bodies[0] = json.dumps(body0, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        assert not verify_chain(heads, bad_bodies), "verify_chain must fail on body mutation"

    # Swap two bodies if n>=2 → should fail (prev links mismatch)
    if n >= 2:
        bad_bodies2 = bodies.copy()
        bad_bodies2[0], bad_bodies2[1] = bad_bodies2[1], bad_bodies2[0]
        assert not verify_chain(heads, bad_bodies2), "verify_chain must fail on order swap"
