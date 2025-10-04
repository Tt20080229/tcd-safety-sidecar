# FILE: tcd/policies.py
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, fields, replace
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError

from .crypto import Blake3Hash
from .detector import TCDConfig
from .risk_av import AlwaysValidConfig

__all__ = [
    "MatchSpec",
    "DetectorOverrides",
    "AVOverrides",
    "RoutingOverrides",
    "ReceiptOptions",
    "SREOptions",
    "PolicyRule",
    "BoundPolicy",
    "PolicyStore",
]


# -------------------------
# Matching helpers
# -------------------------

def _is_regex(p: str) -> bool:
    return isinstance(p, str) and len(p) >= 2 and p.startswith("/") and p.endswith("/")


def _match_token(value: str, pattern: str) -> bool:
    if pattern is None or pattern == "*":
        return True
    if _is_regex(pattern):
        try:
            rgx = re.compile(pattern[1:-1])
            return bool(rgx.fullmatch(value or ""))
        except Exception:
            return False
    return (value or "") == pattern


def _specificity(match: "MatchSpec") -> int:
    score = 0
    for pat in [match.tenant, match.user, match.session, match.model_id, match.gpu_id, match.task, match.lang]:
        if pat is None or pat == "*":
            continue
        score += 1 if _is_regex(pat) else 2
    return score


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _dc_update(dc, override: Dict[str, Any]):
    if not override:
        return dc
    valid = {f.name for f in fields(dc)}
    kwargs = {k: v for k, v in (override or {}).items() if k in valid}
    return replace(dc, **kwargs) if kwargs else dc


# -------------------------
# Schemas
# -------------------------

class MatchSpec(BaseModel):
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"


class DetectorOverrides(BaseModel):
    window_size: Optional[int] = None
    ewma_alpha: Optional[float] = None
    entropy_floor: Optional[float] = None
    spread_threshold: Optional[float] = None
    rel_drop_threshold: Optional[float] = None
    z_threshold: Optional[float] = None
    min_calibration_steps: Optional[int] = None
    hard_fail_on_floor: Optional[bool] = None
    combine_mode: Optional[str] = None
    on_threshold: Optional[float] = None
    off_threshold: Optional[float] = None
    cooldown_steps: Optional[int] = None


class AVOverrides(BaseModel):
    alpha_base: Optional[float] = None


class RoutingOverrides(BaseModel):
    t_low: Optional[float] = None
    t_high: Optional[float] = None
    top_p_low: Optional[float] = None
    top_p_high: Optional[float] = None
    fallback_decoder: Optional[str] = None


class ReceiptOptions(BaseModel):
    enable_issue: bool = False
    enable_verify_metrics: bool = False


class SREOptions(BaseModel):
    slo_latency_ms: Optional[float] = None
    token_cost_divisor: Optional[float] = Field(default=None, ge=1.0)


class PolicyRule(BaseModel):
    name: str
    version: str = "1"
    priority: int = 0
    match: MatchSpec = Field(default_factory=MatchSpec)
    detector: Optional[DetectorOverrides] = None
    av: Optional[AVOverrides] = None
    routing: Optional[RoutingOverrides] = None
    receipt: Optional[ReceiptOptions] = None
    sre: Optional[SREOptions] = None

    def policy_ref(self) -> str:
        payload = {
            "name": self.name,
            "version": self.version,
            "priority": self.priority,
            "match": self.match.model_dump(),
            "detector": self.detector.model_dump() if self.detector else {},
            "av": self.av.model_dump() if self.av else {},
            "routing": self.routing.model_dump() if self.routing else {},
            "receipt": self.receipt.model_dump() if self.receipt else {},
            "sre": self.sre.model_dump() if self.sre else {},
        }
        h = Blake3Hash().hex(_canon_json(payload).encode("utf-8"), ctx="tcd:policy")
        return f"{self.name}@{self.version}#{h[:12]}"


# -------------------------
# Bound output
# -------------------------

@dataclass(frozen=True)
class BoundPolicy:
    name: str
    version: str
    policy_ref: str
    priority: int

    # effective configs
    detector_cfg: TCDConfig
    av_cfg: AlwaysValidConfig

    # routing knobs (None means service default)
    t_low: Optional[float]
    t_high: Optional[float]
    top_p_low: Optional[float]
    top_p_high: Optional[float]
    fallback_decoder: Optional[str]

    # receipt/metrics
    enable_receipts: bool
    enable_verify_metrics: bool

    # SRE knobs
    slo_latency_ms: Optional[float]
    token_cost_divisor: float  # defaulted if None in rule

    # original match (for audit/debug)
    match: Dict[str, str]


# -------------------------
# Policy store
# -------------------------

class PolicyStore:
    def __init__(
        self,
        rules: List[PolicyRule],
        *,
        base_detector: Optional[TCDConfig] = None,
        base_av: Optional[AlwaysValidConfig] = None,
        default_token_cost_divisor: float = 50.0,
    ):
        self._lock = threading.RLock()
        self._rules: List[PolicyRule] = list(rules or [])
        self._base_detector = base_detector or TCDConfig()
        self._base_av = base_av or AlwaysValidConfig()
        self._default_token_cost_divisor = float(default_token_cost_divisor)

    # ---------- construction ----------

    @staticmethod
    def _parse_rules(obj: Any) -> List[PolicyRule]:
        if isinstance(obj, dict) and "rules" in obj and isinstance(obj["rules"], list):
            arr = obj["rules"]
        elif isinstance(obj, list):
            arr = obj
        else:
            return []
        out: List[PolicyRule] = []
        for item in arr:
            try:
                out.append(PolicyRule.model_validate(item))
            except ValidationError:
                continue
        return out

    @classmethod
    def from_env(cls, env_key: str = "TCD_POLICIES_JSON") -> "PolicyStore":
        txt = os.environ.get(env_key, "").strip()
        if not txt:
            return cls(rules=[])
        try:
            obj = json.loads(txt)
        except Exception:
            return cls(rules=[])
        return cls(rules=cls._parse_rules(obj))

    @classmethod
    def from_file(cls, path: str) -> "PolicyStore":
        try:
            with open(path, "r", encoding="utf-8") as fr:
                obj = json.load(fr)
        except Exception:
            return cls(rules=[])
        return cls(rules=cls._parse_rules(obj))

    # ---------- mutation / read ----------

    def replace_rules(self, rules: List[PolicyRule]) -> None:
        with self._lock:
            self._rules = list(rules or [])

    def rules(self) -> List[PolicyRule]:
        with self._lock:
            return list(self._rules)

    # ---------- binding ----------

    @staticmethod
    def _matches(ctx: Dict[str, str], rule: PolicyRule) -> bool:
        m = rule.match
        return (
            _match_token(ctx.get("tenant", ""), m.tenant)
            and _match_token(ctx.get("user", ""), m.user)
            and _match_token(ctx.get("session", ""), m.session)
            and _match_token(ctx.get("model_id", ""), m.model_id)
            and _match_token(ctx.get("gpu_id", ""), m.gpu_id)
            and _match_token(ctx.get("task", ""), m.task)
            and _match_token(ctx.get("lang", ""), m.lang)
        )

    @staticmethod
    def _score(rule: PolicyRule) -> Tuple[int, int]:
        # Higher specificity first, then higher priority.
        return (_specificity(rule.match), int(rule.priority))

    def bind(self, ctx: Dict[str, str]) -> BoundPolicy:
        with self._lock:
            candidates = [r for r in self._rules if self._matches(ctx, r)]
            if not candidates:
                # default fallback
                det = self._base_detector
                av = self._base_av
                return BoundPolicy(
                    name="default",
                    version="0",
                    policy_ref="default@0#000000000000",
                    priority=0,
                    detector_cfg=det,
                    av_cfg=av,
                    t_low=None,
                    t_high=None,
                    top_p_low=None,
                    top_p_high=None,
                    fallback_decoder=None,
                    enable_receipts=False,
                    enable_verify_metrics=False,
                    slo_latency_ms=None,
                    token_cost_divisor=self._default_token_cost_divisor,
                    match={
                        "tenant": "*",
                        "user": "*",
                        "session": "*",
                        "model_id": "*",
                        "gpu_id": "*",
                        "task": "*",
                        "lang": "*",
                    },
                )

            # deterministic selection
            candidates.sort(key=lambda r: self._score(r), reverse=True)
            rule = candidates[0]

            # effective detector cfg
            det = self._base_detector
            if rule.detector:
                det = _dc_update(det, rule.detector.model_dump(exclude_none=True))

            # effective AV cfg
            av = self._base_av
            if rule.av:
                av = _dc_update(av, rule.av.model_dump(exclude_none=True))

            # routing
            r = rule.routing.model_dump(exclude_none=True) if rule.routing else {}
            t_low = r.get("t_low")
            t_high = r.get("t_high")
            top_p_low = r.get("top_p_low")
            top_p_high = r.get("top_p_high")
            fallback_decoder = r.get("fallback_decoder")

            # receipt / metrics
            enable_receipts = bool(rule.receipt.enable_issue) if rule.receipt else False
            enable_verify_metrics = bool(rule.receipt.enable_verify_metrics) if rule.receipt else False

            # SRE
            slo_latency_ms = rule.sre.slo_latency_ms if rule.sre else None
            tcd = rule.sre.token_cost_divisor if (rule.sre and rule.sre.token_cost_divisor) else None
            token_cost_divisor = float(tcd or self._default_token_cost_divisor)

            return BoundPolicy(
                name=rule.name,
                version=rule.version,
                policy_ref=rule.policy_ref(),
                priority=int(rule.priority),
                detector_cfg=det,
                av_cfg=av,
                t_low=t_low,
                t_high=t_high,
                top_p_low=top_p_low,
                top_p_high=top_p_high,
                fallback_decoder=fallback_decoder,
                enable_receipts=enable_receipts,
                enable_verify_metrics=enable_verify_metrics,
                slo_latency_ms=slo_latency_ms,
                token_cost_divisor=token_cost_divisor,
                match=rule.match.model_dump(),
            )

