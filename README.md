tcd-safety-sidecar

Anytime-valid, verifiable safety sidecar for LLMs.
Provides online detection + always-valid (alpha-investing) control, optional verifiable receipts, rate limiting, and SRE-ready observability (Prometheus + OpenTelemetry). HTTP is the primary interface; gRPC is available as an optional shim.

⸻

Table of Contents
	•	Features
	•	Repository layout
	•	Quick start
	•	HTTP API
	•	Verifiable receipts
	•	Rate limiting & always-valid control
	•	Observability
	•	gRPC (optional)
	•	CLI tools
	•	Helm & Kubernetes
	•	Storage helpers (optional)
	•	Configuration
	•	Development
	•	License
	•	Security & notes

⸻

Features
	•	HTTP service (FastAPI): /diagnose, /verify, /healthz, /version, /state/*
	•	Always-valid controller: e-process + alpha-investing to manage per-subject budget
	•	Routing on degrade: returns temperature/top-p adjustments/tags
	•	Optional verifiable receipts: deterministic head/body/sig triplet (+ chain verify)
	•	Rate limiting: per (tenant,user,session) token bucket
	•	Observability: Prometheus metrics + OTEL export; Prometheus alert rules included
	•	CLI tools:
	•	tcd-verify: verify a single receipt or a chain
	•	tcd-replay: replay JSONL/synthetic traffic to /diagnose and summarize latency
	•	gRPC (optional): register handlers into an existing grpc.Server
	•	Storage helpers (optional): SQLite/in-memory ledgers & receipt stores

The service composes detectors, controllers, exporters, and routing from the tcd package. Configuration is environment-driven (see tcd/config.py in the repo).

⸻

Repository layout

.
├── Dockerfile
├── Makefile
├── deploy/helm/               # Helm chart (values override env for the Pod)
├── ops/alerts/prometheus-rules.yaml
├── tcd/
│   ├── __init__.py
│   ├── admin_http.py          # (admin-only HTTP handlers, if enabled)
│   ├── service_http.py        # FastAPI app factory (primary entry)
│   ├── service_grpc.py        # gRPC shim (optional, stubs required)
│   ├── cli/
│   │   ├── serve_http.py      # CLI: run HTTP server (uvicorn)
│   │   ├── verify.py          # CLI: verify receipt / chain
│   │   └── replay.py          # CLI: replay traffic to /diagnose
│   ├── api/proto/tcd.proto    # gRPC service definition (source .proto)
│   ├── ledger.py              # (optional) SQLite/in-memory ledger for alpha wealth & receipts
│   ├── storage.py             # (optional) generic ledger/receipt stores (SQLite/mem)
│   ├── exporter.py, otel_exporter.py, ratelimit.py, routing.py, ...
│   ├── detector.py, risk_av.py, multivariate.py, signals.py, utils.py, ...
│   └── verify.py              # verify_chain / verify_receipt
└── tests/property/            # property/quick tests (if enabled)


⸻

Quick start

1) Run the HTTP sidecar (Python)

# (venv recommended)
python -m tcd.cli.serve_http --host 0.0.0.0 --port 8080
# or rely on env-driven defaults; see `tcd/config.py`

2) Or run with Docker

docker build -t tcd-sidecar .
docker run --rm -p 8080:8080 \
  -e TCD_RECEIPTS_ENABLE=1 \
  -e TCD_HASH_ALG=blake3 \
  tcd-sidecar

3) Send a sample /diagnose

curl -s http://127.0.0.1:8080/diagnose \
  -H 'content-type: application/json' -d '{
    "trace_vector":[0.1,0.2,0.3],
    "spectrum":[0.01,0.02],
    "entropy":1.2,
    "features":[0.5,0.4],
    "model_id":"m0","gpu_id":"g0","task":"chat","lang":"en",
    "tenant":"t0","user":"u0","session":"s0",
    "context":{"temperature":0.7,"top_p":0.9},
    "tokens_delta":50,"drift_score":0.0
  }' | jq .

You’ll receive a RiskResponse:

{
  "verdict": false,
  "score": 0.12,
  "threshold": 0.0,
  "budget_remaining": 0.05,
  "components": { "...": { } },
  "cause": "",
  "action": "none",
  "step": 3,
  "e_value": 1.0,
  "alpha_alloc": 0.0,
  "alpha_spent": 0.0,

  // present only when receipts are enabled
  "receipt": "abcd…",
  "receipt_body": "{…canonical JSON…}",
  "receipt_sig": "ed25519…",
  "verify_key": "ed25519…"
}

4) (Optional) Verify the receipt

python -m tcd.cli.verify receipt \
  --head "<receipt hex>" \
  --body '<canonical json string>' \
  --vk "<verify key hex>" \
  --sig "<signature hex>" \
  --json

5) (Optional) Replay traffic

python -m tcd.cli.replay --synthetic --count 128 --concurrency 8 --verify --json


⸻

HTTP API

Endpoints
	•	GET /healthz → {"ok": true, "config_hash": "...", "otel": bool, "prom": true, "receipts": bool?}
	•	GET /version → version/config summary (includes alpha, slo_latency_ms)
	•	GET /state/get?model_id=&gpu_id=&task=&lang= → detector snapshot
	•	POST /state/load → load detector state { "state": {...} }
	•	POST /diagnose → core decision endpoint (see models below)
	•	POST /verify → verify a single receipt or a chain

Models (JSON)

DiagnoseRequest

{
  "trace_vector": [float],        // capped; sanitized
  "entropy": 1.2,                 // optional
  "spectrum": [float],            // capped
  "features": [float],            // optional, aux-only
  "step_id": 0,                   // optional

  "model_id": "model0",
  "gpu_id": "gpu0",
  "task": "chat",
  "lang": "en",
  "tenant": "tenant0",
  "user": "user0",
  "session": "sess0",

  "context": { },                 // temperature/top_p etc
  "tokens_delta": 50,             // approx cost for rate limiting
  "drift_score": 0.0              // modulates thresholds/investing
}

RiskResponse (core fields)

{
  "verdict": true|false,          // fail if detector OR AV triggers
  "score": 0.0..1.0,
  "threshold": 0.0,
  "budget_remaining": 0.0,        // AV alpha wealth
  "components": { "…" : { } },    // detector internals (JSON)
  "cause": "detector"|"av"|"",
  "action": "degrade"|"none",
  "step": 0,
  "e_value": 1.0,
  "alpha_alloc": 0.0,
  "alpha_spent": 0.0,

  // present only when receipts are enabled
  "receipt": "hex",
  "receipt_body": "canonical-json",
  "receipt_sig": "hex",
  "verify_key": "hex"
}

VerifyRequest (two modes)
	•	Single receipt:
	•	receipt_head_hex, receipt_body_json, verify_key_hex?, receipt_sig_hex?,
	•	optional req_obj, comp_obj, e_obj, witness_segments
	•	Chain:
	•	heads (array of hex), bodies (array of canonical JSON)

VerifyResponse

{ "ok": true }


⸻

Verifiable receipts

Enable issuance via env:

export TCD_RECEIPTS_ENABLE=1
# optional; defaults to blake3
export TCD_HASH_ALG=blake3

When enabled, /diagnose returns an inlined receipt triplet:
	•	receipt (head hex), receipt_body (canonical JSON), receipt_sig (optional Ed25519),
	•	verify_key (optional Ed25519 verify key)

You can verify either:
	•	single receipt via /verify or tcd-verify receipt
	•	chain (aligned arrays of heads/bodies) via /verify or tcd-verify chain

⸻

Rate limiting & always-valid control
	•	Rate limit: token bucket per (tenant,user,session) using tokens_delta as cost hint; returns HTTP 429 on throttle.
	•	Always-valid (AV): conservatively maps score → p and updates per-subject e-process/alpha wealth; final decision is:
	•	verdict = detector_trigger OR av_trigger.

⸻

Observability
	•	Prometheus: exposed via the built-in exporter (TCDPrometheusExporter).
Prometheus alert rules are provided at ops/alerts/prometheus-rules.yaml.
	•	OpenTelemetry: exporter (TCDOtelExporter) pushes metrics/spans when enabled.

Exact env keys for ports/endpoints come from tcd/config.py. Set the OTLP HTTP endpoint via the exporter’s endpoint variable (e.g. TCD_OTEL_ENDPOINT used by the CLIs).

⸻

gRPC (optional)

The HTTP semantics are mirrored via a gRPC service, but stubs are optional at runtime.

1) Generate Python stubs

Source proto: tcd/api/proto/tcd.proto. Generate stubs into tcd/proto/ so imports like from tcd.proto import tcd_pb2 work:

python -m grpc_tools.protoc \
  -I tcd/api/proto \
  --python_out=tcd/proto \
  --grpc_python_out=tcd/proto \
  tcd/api/proto/tcd.proto

# Ensure `tcd/proto/__init__.py` exists

2) Register services

from concurrent import futures
import grpc
from tcd.service_grpc import register_grpc_services

server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
ok = register_grpc_services(server)  # returns False if stubs are missing
if not ok:
    raise RuntimeError("gRPC stubs not found. Generate from tcd/api/proto/tcd.proto.")
server.add_insecure_port("0.0.0.0:9090")
server.start(); server.wait_for_termination()


⸻

CLI tools

tcd-verify (receipt/chain)

# single receipt
python -m tcd.cli.verify receipt \
  --head @head.hex \
  --body @body.json \
  --vk <verify-key-hex> \
  --sig <sig-hex> \
  --json

# chain (JSONL: each line has {receipt, receipt_body})
python -m tcd.cli.verify chain --jsonl --heads receipts.jsonl --json

tcd-replay (traffic replay)

# synthetic
python -m tcd.cli.replay --synthetic --count 256 --concurrency 8 --verify --json

# replay JSONL (one DiagnoseRequest per line)
python -m tcd.cli.replay --jsonl requests.jsonl --concurrency 8 --verify

Both CLIs can export Prometheus/OTel metrics (see flags/help).

⸻

Helm & Kubernetes

A basic Helm chart is provided under deploy/helm/.
Typical overrides:
	•	container image/tag
	•	service port
	•	environment variables (e.g., enable receipts, OTEL endpoint)
	•	resources/limits and Prometheus scrape annotations

⸻

Storage helpers (optional)

Modules tcd/ledger.py and tcd/storage.py provide SQLite/in-memory implementations for:
	•	alpha wealth ledgers (idempotent apply via idem keys)
	•	receipt stores (append, latest, walk back, integrity check)

These are not required by the HTTP service by default, but are available for deployments that want durable wealth/chain storage.

⸻

Configuration
	•	The service reads env-driven settings via tcd.config.make_reloadable_settings().
	•	Confirmed toggles:
	•	TCD_RECEIPTS_ENABLE=1 – enable receipt issuance
	•	TCD_HASH_ALG=blake3 – digest algorithm for commits
	•	OTEL/Prometheus/other runtime ports/flags are also env-driven; check tcd/config.py and exporters.

⸻

Development
	•	Run the HTTP server: python -m tcd.cli.serve_http --host 0.0.0.0 --port 8080
	•	Verify receipts: python -m tcd.cli.verify --help
	•	Replay traffic: python -m tcd.cli.replay --help
	•	Build container: docker build -t tcd-sidecar .

(See Makefile for additional shortcuts if present.)

⸻

License

Apache-2.0 (see LICENSE).

⸻

Security & notes
	•	The detector, thresholds, and investing policies are configurable; validate against your own datasets.
	•	Receipts provide verifiable traceability, not a legal compliance guarantee.
	•	Arrays and payload sizes are sanitized and bounded; misuse returns HTTP 400/429.
