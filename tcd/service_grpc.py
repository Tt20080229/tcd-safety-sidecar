# FILE: tcd/service_grpc.py
"""
gRPC service shim for TCD — mirrors the HTTP semantics (/diagnose, /verify) while
remaining an optional, non-entry dependency. This module:
  - Only activates if `grpcio` and generated stubs (`tcd/proto/*_pb2*.py`) are importable.
  - Reuses the same decision pipeline as HTTP (detector + AV controller + routing + metrics).
  - Adds production-grade guardrails: deadlines, rate limiting, structured errors.
  - Exposes a single helper `register_grpc_services(server)` that safely no-ops if stubs missing.

Why not a CLI entrypoint?
  The repo avoids hard dependencies on generated stubs. You may build your own gRPC server
  in your deployment repo and call `register_grpc_services(server)` to attach handlers.

Proto expectations (not bundled here):
  service TcdService {
    rpc Diagnose(DiagnoseRequest) returns (RiskResponse);
    rpc Verify(VerifyRequest) returns (VerifyResponse);
  }
  // Fields mirror FastAPI models in service_http.py (with obvious typing adaptations).
"""
from __future__ import annotations

import json
import threading
import time
from typing import Dict, List, Optional, Tuple

try:
    import grpc  # type: ignore
    _HAS_GRPC = True
except Exception:  # pragma: no cover
    grpc = None  # type: ignore
    _HAS_GRPC = False

# Attempt to import generated stubs (optional)
try:
    # Expect files like: tcd/proto/tcd_pb2.py, tcd/proto/tcd_pb2_grpc.py
    from .proto import tcd_pb2 as pb  # type: ignore
    from .proto import tcd_pb2_grpc as pb_grpc  # type: ignore
    _HAS_STUBS = True
except Exception:  # pragma: no cover
    pb = None  # type: ignore
    pb_grpc = None  # type: ignore
    _HAS_STUBS = False

# Shared pipeline bits (aligned with HTTP service)
from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .ratelimit import RateLimiter
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .routing import StrategyRouter
from .utils import sanitize_floats
from .verify import verify_chain, verify_receipt

_settings = make_reloadable_settings()


# ---------- Utilities & Conversions ----------

def _p_cons(score: float) -> float:
    """Conservative monotone map score∈[0,1] → p∈(0,1]; higher score = smaller p."""
    s = max(0.0, min(1.0, float(score)))
    return max(1e-9, 1.0 - s)


def _err(context, code, msg: str):
    # Map to gRPC status
    if not _HAS_GRPC:  # pragma: no cover
        return
    context.set_code(code)
    context.set_details(msg)


# ---------- Core runtime (mirrors HTTP create_app pipeline) ----------

class _Runtime:
    """Holds long-lived singletons (detectors, AV controllers, metrics)."""

    def __init__(self):
        self.settings = _settings.get()

        self.prom = TCDPrometheusExporter(
            port=self.settings.prometheus_port,
            version="0.10.2",
            config_hash=self.settings.config_hash(),
        )
        if self.settings.prom_http_enable:
            self.prom.ensure_server()

        self.otel = (
            TCDOtelExporter(endpoint=self.settings.otel_endpoint)
            if self.settings.otel_enable
            else TCDOtelExporter(endpoint=self.settings.otel_endpoint)
        )

        self.rlim = RateLimiter(capacity=60.0, refill_per_s=30.0)

        self.det_lock = threading.RLock()
        self.detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = {}

        self.av_lock = threading.RLock()
        self.av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = {}

        self.mv_lock = threading.RLock()
        self.mv_by_model: Dict[str, MultiVarDetector] = {}

        self.router = StrategyRouter()

    # Accessors
    def get_detector(self, key: Tuple[str, str, str, str]) -> TraceCollapseDetector:
        with self.det_lock:
            inst = self.detectors.get(key)
            if inst is None:
                inst = TraceCollapseDetector(config=TCDConfig())
                self.detectors[key] = inst
            return inst

    def get_av(self, subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with self.av_lock:
            inst = self.av_by_subject.get(subject)
            if inst is None:
                inst = AlwaysValidRiskController(AlwaysValidConfig(alpha_base=self.settings.alpha))
                self.av_by_subject[subject] = inst
            return inst

    def get_mv(self, model_id: str) -> MultiVarDetector:
        with self.mv_lock:
            inst = self.mv_by_model.get(model_id)
            if inst is None:
                inst = MultiVarDetector(MultiVarConfig(estimator="lw", alpha=0.01))
                self.mv_by_model[model_id] = inst
            return inst


_runtime: Optional[_Runtime] = None


def _rt() -> _Runtime:
    global _runtime
    if _runtime is None:
        _runtime = _Runtime()
    return _runtime


# ---------- Service Implementation (only if stubs exist) ----------

if _HAS_GRPC and _HAS_STUBS:

    class TcdService(pb_grpc.TcdServiceServicer):  # type: ignore
        """
        gRPC service implementing Diagnose/Verify with semantics consistent with HTTP endpoints.
        """

        # -------- Diagnose --------
        def Diagnose(self, request: "pb.DiagnoseRequest", context: "grpc.ServicerContext"):  # type: ignore
            rt = _rt()
            t0 = time.perf_counter()

            # Basic payload limits to guard against abuse
            if len(request.trace_vector) > 4096 or len(request.spectrum) > 4096 or len(request.features) > 2048:
                _err(context, grpc.StatusCode.INVALID_ARGUMENT, "payload too large")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False,
                    score=0.0,
                    threshold=0.0,
                    budget_remaining=0.0,
                    components=json.dumps({"error": "payload too large"}),
                    cause="",
                    action="reject",
                    step=0,
                    e_value=1.0,
                    alpha_alloc=0.0,
                    alpha_spent=0.0,
                )

            # Rate limiting per subject (tenant/user/session)
            subject = (request.tenant or "tenant0", request.user or "user0", request.session or "sess0")
            cost = max(1.0, float(request.tokens_delta or 50) / 50.0)
            if not rt.rlim.consume(subject, cost=cost):
                rt.prom.throttle(*subject, reason="rate")
                _err(context, grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limited")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False, score=0.0, threshold=0.0, budget_remaining=0.0,
                    components=json.dumps({"error": "rate_limited"}), cause="rate", action="reject",
                    step=0, e_value=1.0, alpha_alloc=0.0, alpha_spent=0.0
                )

            # Sanitize arrays
            trace_vec, _ = sanitize_floats(list(request.trace_vector), max_len=4096)
            spectrum, _ = sanitize_floats(list(request.spectrum), max_len=4096)
            features, _ = sanitize_floats(list(request.features), max_len=2048)

            # Diagnose via detector (hysteresis inside)
            dkey = (request.model_id or "model0", request.gpu_id or "gpu0", request.task or "chat", request.lang or "en")
            det = rt.get_detector(dkey)
            entropy = None if request.HasField("entropy") is False else float(request.entropy)  # type: ignore
            vp = det.diagnose(trace_vec, entropy, spectrum, step_id=request.step_id if request.step_id else None)

            # Optional multivariate score (aux only)
            mv_info = {}
            if len(features) > 0:
                try:
                    mv = rt.get_mv(request.model_id or "model0")
                    mv_info = mv.decision(features)  # returns dict
                except Exception:
                    mv_info = {}

            # Score → p-value (conservative)
            score = float(vp.get("score", 0.0))
            p_final = _p_cons(score)

            # AV controller step
            av = rt.get_av(subject)
            drift_w = max(0.0, min(2.0, 1.0 + 0.5 * float(request.drift_score if request.HasField("drift_score") else 0.0)))  # type: ignore
            av_out = av.step(
                policy_key=(request.task or "chat", request.lang or "en", request.model_id or "model0"),
                subject=subject, scores={"final": score}, pvals={"final": p_final}, drift_weight=drift_w
            )

            decision_fail = bool(vp.get("verdict", False) or av_out.get("trigger", False))

            # Record metrics
            latency_s = max(0.0, time.perf_counter() - t0)
            rt.prom.observe_latency(latency_s)
            rt.prom.push(vp, labels={"model_id": request.model_id or "model0", "gpu_id": request.gpu_id or "gpu0"})
            rt.prom.push_eprocess(
                model_id=request.model_id or "model0", gpu_id=request.gpu_id or "gpu0",
                tenant=subject[0], user=subject[1], session=subject[2],
                e_value=float(av_out.get("e_value", 1.0)), alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
            )
            rt.prom.update_budget_metrics(
                subject[0], subject[1], subject[2],
                remaining=float(av_out.get("alpha_wealth", 0.0)),
                spent=bool(av_out.get("alpha_spent", 0.0) > 0.0),
            )
            if decision_fail:
                rt.prom.record_action(request.model_id or "model0", request.gpu_id or "gpu0", action="degrade")
            if (latency_s * 1000.0) > float(rt.settings.slo_latency_ms):
                rt.prom.slo_violation_by_model("diagnose_latency", request.model_id or "model0", request.gpu_id or "gpu0")

            # Build response
            # components is a JSON-encoded map to avoid proto bloat (keeps stubs simple)
            comps_json = json.dumps(vp.get("components", {}))
            cause = "detector" if bool(vp.get("verdict", False)) else ("av" if bool(av_out.get("trigger", False)) else "")
            action = "degrade" if decision_fail else "none"

            return pb.RiskResponse(  # type: ignore
                verdict=decision_fail,
                score=score,
                threshold=float(av_out.get("threshold", 0.0)),
                budget_remaining=float(av_out.get("alpha_wealth", 0.0)),
                components=comps_json,
                cause=cause,
                action=action,
                step=int(vp.get("step", 0)),
                e_value=float(av_out.get("e_value", 1.0)),
                alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                alpha_spent=float(av_out.get("alpha_spent", 0.0)),
            )

        # -------- Verify --------
        def Verify(self, request: "pb.VerifyRequest", context: "grpc.ServicerContext"):  # type: ignore
            rt = _rt()
            t0 = time.perf_counter()

            ok = False
            try:
                # Chain verification takes precedence if both heads/bodies present
                has_chain = (len(request.heads) > 0) or (len(request.bodies) > 0)
                if has_chain:
                    if len(request.heads) != len(request.bodies) or len(request.heads) == 0:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "heads/bodies must align and be non-empty")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    ok = bool(verify_chain(list(request.heads), list(request.bodies)))
                else:
                    if not request.receipt_head_hex or not request.receipt_body_json:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "missing receipt head/body")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    witness = None
                    # Optional witness segments (trace/spectrum/feat)
                    if (len(request.witness_trace) + len(request.witness_spectrum) + len(request.witness_feat)) > 0:
                        witness = (
                            list(int(x) for x in request.witness_trace),
                            list(int(x) for x in request.witness_spectrum),
                            list(int(x) for x in request.witness_feat),
                        )
                    # Optional req/comp/e objects as JSON strings in proto; decode if present
                    def _maybe(obj: str) -> Optional[Dict]:
                        if not obj:
                            return None
                        try:
                            return json.loads(obj)
                        except Exception:
                            return None

                    ok = bool(
                        verify_receipt(
                            receipt_head_hex=str(request.receipt_head_hex),
                            receipt_body_json=str(request.receipt_body_json),
                            verify_key_hex=(str(request.verify_key_hex) if request.verify_key_hex else None),
                            receipt_sig_hex=(str(request.receipt_sig_hex) if request.receipt_sig_hex else None),
                            req_obj=_maybe(request.req_json),
                            comp_obj=_maybe(request.comp_json),
                            e_obj=_maybe(request.e_json),
                            witness_segments=witness,
                            strict=True,
                        )
                    )
            finally:
                rt.prom.observe_latency(max(0.0, time.perf_counter() - t0))
                if not ok:
                    rt.prom.slo_violation("verify_fail")
            return pb.VerifyResponse(ok=bool(ok))  # type: ignore


# ---------- Public API ----------

def grpc_supported() -> bool:
    """Return True if grpcio and generated stubs are importable."""
    return bool(_HAS_GRPC and _HAS_STUBS)


def register_grpc_services(server: "grpc.Server") -> bool:  # type: ignore
    """
    Attach TCD gRPC services to an existing `grpc.Server`.
    Returns True if services were registered; False if stubs are unavailable.

    Usage (in your own entrypoint):
        import grpc
        from tcd.service_grpc import register_grpc_services

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        if not register_grpc_services(server):
            raise RuntimeError("TCD gRPC stubs not found; did you generate and install them?")
        server.add_insecure_port("0.0.0.0:9090")
        server.start(); server.wait_for_termination()
    """
    if not grpc_supported():  # pragma: no cover
        return False
    pb_grpc.add_TcdServiceServicer_to_server(TcdService(), server)  # type: ignore
    return True
