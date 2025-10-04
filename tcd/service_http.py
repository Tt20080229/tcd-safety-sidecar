from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .ratelimit import RateLimiter
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .routing import StrategyRouter
from .signals import DefaultLLMSignals, SignalProvider
from .telemetry_gpu import GpuSampler
from .utils import sanitize_floats
from .verify import verify_chain, verify_receipt  # optional receipt verification for /verify

_settings = make_reloadable_settings()


# ---------- Pydantic I/O ----------

class DiagnoseRequest(BaseModel):
    # Observed signals
    trace_vector: List[float] = Field(default_factory=list)
    entropy: Optional[float] = None
    spectrum: List[float] = Field(default_factory=list)
    features: List[float] = Field(default_factory=list)  # optional multivariate features
    step_id: Optional[int] = None

    # Identifiers
    model_id: str = "model0"
    gpu_id: str = "gpu0"
    task: str = "chat"
    lang: str = "en"
    tenant: str = "tenant0"
    user: str = "user0"
    session: str = "sess0"

    # Context and rough cost estimate
    context: Dict = Field(default_factory=dict)
    tokens_delta: int = 50
    drift_score: float = 0.0  # drift intensity used to modulate thresholds/investing


class RiskResponse(BaseModel):
    verdict: bool
    score: float
    threshold: float
    budget_remaining: float
    components: Dict[str, Dict]
    cause: Optional[str] = None
    action: Optional[str] = None
    step: int
    e_value: float
    alpha_alloc: float
    alpha_spent: float


class SnapshotState(BaseModel):
    state: Dict


class VerifyRequest(BaseModel):
    # Single-receipt verification fields
    receipt_head_hex: Optional[str] = None
    receipt_body_json: Optional[str] = None
    verify_key_hex: Optional[str] = None
    receipt_sig_hex: Optional[str] = None
    req_obj: Optional[Dict] = None
    comp_obj: Optional[Dict] = None
    e_obj: Optional[Dict] = None
    # Witness segments (three int lists for trace/spectrum/feat)
    witness_segments: Optional[Tuple[List[int], List[int], List[int]]] = None

    # Chain verification (mutually exclusive with the above single-receipt set)
    heads: Optional[List[str]] = None
    bodies: Optional[List[str]] = None


class VerifyResponse(BaseModel):
    ok: bool


# ---------- App factory ----------

def create_app() -> FastAPI:
    app = FastAPI(title="tcd-sidecar", version="0.10.2")

    # Settings & observability
    settings = _settings.get()
    prom = TCDPrometheusExporter(
        port=settings.prometheus_port,
        version="0.10.2",
        config_hash=settings.config_hash(),
    )
    if settings.prom_http_enable:
        prom.ensure_server()

    # OTEL exporter (no-op if disabled/missing deps)
    otel = TCDOtelExporter(endpoint=settings.otel_endpoint)

    # Signal provider & optional GPU sampler
    signals: SignalProvider = DefaultLLMSignals()
    gpu = GpuSampler(0) if settings.gpu_enable else None

    # Per-tenant token-bucket rate limit (tokens_delta approximates cost)
    rlim = RateLimiter(capacity=60.0, refill_per_s=30.0)

    # Detector by (model,gpu,task,lang); AV controller by (tenant,user,session)
    det_lock = threading.RLock()
    detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = {}

    av_lock = threading.RLock()
    av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = {}

    # Optional multivariate detector (placeholder for future extension/training)
    mv_lock = threading.RLock()
    mv_by_model: Dict[str, MultiVarDetector] = {}

    router = StrategyRouter()

    def _get_detector(key: Tuple[str, str, str, str]) -> TraceCollapseDetector:
        with det_lock:
            if key not in detectors:
                detectors[key] = TraceCollapseDetector(config=TCDConfig())
            return detectors[key]

    def _get_av(subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with av_lock:
            if subject not in av_by_subject:
                av_by_subject[subject] = AlwaysValidRiskController(
                    AlwaysValidConfig(alpha_base=settings.alpha)
                )
            return av_by_subject[subject]

    def _get_mv(model_id: str) -> MultiVarDetector:
        with mv_lock:
            if model_id not in mv_by_model:
                mv_by_model[model_id] = MultiVarDetector(
                    MultiVarConfig(estimator="lw", alpha=0.01)
                )
            return mv_by_model[model_id]

    def _conservative_p_from_score(score: float) -> float:
        # Monotone & conservative: higher score -> smaller p; clamp to [1e-9, 1]
        s = max(0.0, min(1.0, float(score)))
        p = 1.0 - s
        return max(1e-9, min(1.0, p))

    # ---------- Endpoints ----------

    @app.get("/healthz")
    def healthz():
        return {
            "ok": True,
            "config_hash": settings.config_hash(),
            "otel": bool(getattr(otel, "enabled", False)),
            "prom": True,
        }

    @app.get("/version")
    def version():
        return {
            "version": "0.10.2",
            "config_version": settings.config_version,
            "alpha": settings.alpha,
            "slo_latency_ms": settings.slo_latency_ms,
        }

    @app.get("/state/get")
    def state_get(
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
    ):
        det = _get_detector((model_id, gpu_id, task, lang))
        return {"detector": det.snapshot_state()}

    @app.post("/state/load")
    def state_load(
        payload: SnapshotState,
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
    ):
        det = _get_detector((model_id, gpu_id, task, lang))
        det.load_state(payload.state)
        return {"ok": True}

    @app.post("/diagnose", response_model=RiskResponse)
    def diagnose(req: DiagnoseRequest):
        t_start = time.perf_counter()

        # Rate limit by (tenant,user,session); tokens_delta approximates cost
        key = (req.tenant, req.user, req.session)
        cost = max(1.0, float(req.tokens_delta) / 50.0)
        if not rlim.consume(key, cost=cost):
            prom.throttle(req.tenant, req.user, req.session, reason="rate")
            raise HTTPException(status_code=429, detail="rate limited")

        # Optional GPU sampling appended to context for observability
        if gpu is not None:
            try:
                req.context.update(gpu.sample())
            except Exception:
                pass  # sampling failure must not affect main path

        # Sanitize numeric inputs (NaN/Inf/range; enforce length caps)
        trace_vec, _ = sanitize_floats(req.trace_vector, max_len=4096)
        spectrum, _ = sanitize_floats(req.spectrum, max_len=4096)
        features, _ = sanitize_floats(req.features, max_len=2048)

        # Get/initialize detector
        dkey = (req.model_id, req.gpu_id, req.task, req.lang)
        det = _get_detector(dkey)

        # Run diagnosis (with hysteresis)
        verdict_pack = det.diagnose(trace_vec, req.entropy, spectrum, step_id=req.step_id)

        # Optional multivariate scoring (auxiliary only; does not change final verdict)
        mv_info: Dict[str, float] = {}
        if features:
            try:
                mv = _get_mv(req.model_id)
                mv_info = mv.decision(np.asarray(features, dtype=float))  # {distance, threshold, trigger}
            except Exception:
                mv_info = {}

        # Unified risk score from detector
        score = float(verdict_pack.get("score", 0.0))
        p_final = _conservative_p_from_score(score)

        # Always-Valid controller (e-process + alpha-investing)
        subject = (req.tenant, req.user, req.session)
        av = _get_av(subject)
        av_out = av.step(
            policy_key=(req.task, req.lang, req.model_id),
            subject=subject,
            scores={"final": score},
            pvals={"final": p_final},
            drift_weight=float(max(0.0, min(2.0, 1.0 + 0.5 * float(req.drift_score)))),
        )

        # Final decision: detector trigger OR AV trigger -> FAIL
        decision_fail = bool(verdict_pack.get("verdict", False) or av_out.get("trigger", False))

        # Degradation routing (temperature/top-p/decoder). Route is returned to caller.
        route = router.decide(
            decision_fail,
            score,
            base_temp=float(req.context.get("temperature", 0.7)),
            base_top_p=float(req.context.get("top_p", 0.9)),
        )

        # Prom/OTel metrics
        latency_s = max(0.0, time.perf_counter() - t_start)
        prom.observe_latency(latency_s)
        prom.push(verdict_pack, labels={"model_id": req.model_id, "gpu_id": req.gpu_id})
        prom.push_eprocess(
            model_id=req.model_id,
            gpu_id=req.gpu_id,
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            e_value=float(av_out.get("e_value", 1.0)),
            alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
            alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
        )
        prom.update_budget_metrics(
            req.tenant,
            req.user,
            req.session,
            remaining=float(av_out.get("alpha_wealth", 0.0)),
            spent=bool(av_out.get("alpha_spent", 0.0) > 0.0),
        )
        if decision_fail:
            prom.record_action(req.model_id, req.gpu_id, action="degrade")
        otel.push_metrics(
            score,
            attrs={
                "model_id": req.model_id,
                "gpu_id": req.gpu_id,
                "tenant": req.tenant,
                "user": req.user,
                "session": req.session,
            },
        )

        # SLO guard: count violations when latency exceeds threshold
        if (latency_s * 1000.0) > float(settings.slo_latency_ms):
            prom.slo_violation_by_model("diagnose_latency", req.model_id, req.gpu_id)

        return RiskResponse(
            verdict=bool(decision_fail),
            score=score,
            threshold=float(av_out.get("threshold", 0.0)),
            budget_remaining=float(av_out.get("alpha_wealth", 0.0)),
            components=verdict_pack.get("components", {}),
            cause=("detector" if verdict_pack.get("verdict", False) else ("av" if av_out.get("trigger", False) else "")),
            action=("degrade" if decision_fail else "none"),
            step=int(verdict_pack.get("step", 0)),
            e_value=float(av_out.get("e_value", 1.0)),
            alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
            alpha_spent=float(av_out.get("alpha_spent", 0.0)),
        )

    @app.post("/verify", response_model=VerifyResponse)
    def verify(req: VerifyRequest):
        t0 = time.perf_counter()
        ok = False
        try:
            # Chain verification first
            if req.heads is not None and req.bodies is not None:
                if (
                    not isinstance(req.heads, list)
                    or not isinstance(req.bodies, list)
                    or len(req.heads) != len(req.bodies)
                ):
                    raise HTTPException(status_code=400, detail="heads/bodies invalid")
                ok = bool(verify_chain(req.heads, req.bodies))
            else:
                if not req.receipt_head_hex or not req.receipt_body_json:
                    raise HTTPException(status_code=400, detail="missing receipt head/body")
                ws = None
                if req.witness_segments is not None:
                    if (
                        len(req.witness_segments) != 3
                        or any(not isinstance(seg, list) for seg in req.witness_segments)
                    ):
                        raise HTTPException(
                            status_code=400,
                            detail="witness_segments must be triple of int lists",
                        )
                    ws = (
                        req.witness_segments[0],
                        req.witness_segments[1],
                        req.witness_segments[2],
                    )
                ok = bool(
                    verify_receipt(
                        receipt_head_hex=req.receipt_head_hex,
                        receipt_body_json=req.receipt_body_json,
                        verify_key_hex=req.verify_key_hex,
                        receipt_sig_hex=req.receipt_sig_hex,
                        req_obj=req.req_obj,
                        comp_obj=req.comp_obj,
                        e_obj=req.e_obj,
                        witness_segments=ws,
                        strict=True,
                    )
                )
        finally:
            prom.observe_latency(max(0.0, time.perf_counter() - t0))
            if not ok:
                prom.slo_violation("verify_fail")
        return VerifyResponse(ok=ok)

    return app

# FILE: tcd/cli/serve_http.py
from __future__ import annotations

import signal
import sys
from typing import Optional

import click
import uvicorn

from ..config import make_reloadable_settings
from ..service_http import create_app


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default=None, help="Bind host (override settings.host)")
@click.option("--port", type=int, default=None, help="Bind port (override settings.port)")
@click.option("--log-level", default="info", show_default=True, help="uvicorn log level")
def main(host: Optional[str], port: Optional[int], log_level: str) -> None:
    """
    Launch the TCD HTTP sidecar (FastAPI).

    Sources of truth:
      - ServiceSettings (env-driven) for defaults.
      - CLI flags override env.
    """
    settings = make_reloadable_settings().get()
    bind_host = host or settings.host or "0.0.0.0"
    bind_port = int(port or settings.port or 8080)

    app = create_app()

    # Graceful shutdown
    def _graceful_exit(*_):
        sys.exit(0)

    try:
        signal.signal(signal.SIGTERM, _graceful_exit)
        signal.signal(signal.SIGINT, _graceful_exit)
    except Exception:
        # Some platforms (e.g., Windows) may restrict signals; ignore
        pass

    uvicorn.run(app, host=bind_host, port=bind_port, log_level=log_level)


if __name__ == "__main__":
    main()
