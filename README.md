# tcd-safety-sidecar

Anytime-valid, verifiable safety sidecar for LLMs. Online detection + always-valid (alpha-investing) control, optional verifiable receipts, rate limiting, and SRE-ready observability (Prometheus + OpenTelemetry). Primary interface: HTTP; optional gRPC shim.

<p align="center">
  <a href="#table-of-contents">Table of Contents</a> ·
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#http-api">HTTP API</a> ·
  <a href="#verifiable-receipts">Receipts</a> ·
  <a href="#rate-limiting--always-valid-control">AV control</a> ·
  <a href="#observability">Observability</a> ·
  <a href="#grpc-optional">gRPC</a> ·
  <a href="#cli-tools">CLI</a> ·
  <a href="#helm--kubernetes">Helm</a> ·
  <a href="#storage-helpers-optional">Storage</a> ·
  <a href="#configuration">Config</a> ·
  <a href="#development">Development</a> ·
  <a href="#security--notes">Security</a>
</p>

## Table of Contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [HTTP API](#http-api)
- [Verifiable receipts](#verifiable-receipts)
- [Rate limiting & always-valid control](#rate-limiting--always-valid-control)
- [Observability](#observability)
- [gRPC (optional)](#grpc-optional)
- [CLI tools](#cli-tools)
- [Helm & Kubernetes](#helm--kubernetes)
- [Storage helpers (optional)](#storage-helpers-optional)
- [Configuration](#configuration)
- [Development](#development)
- [Security & notes](#security--notes)
- [License](#license)


## Features

- HTTP service (FastAPI): `/diagnose`, `/verify`, `/healthz`, `/version`, `/state/*`
- **Always-valid controller**: e-process + alpha-investing (per-subject budget)
- **Routing on degrade**: returns temperature / top-p adjustments + tags
- **Verifiable receipts**: deterministic `head`/`body`/`sig` triplet (+ chain verify)
- **Rate limiting**: token bucket per `(tenant, user, session)`
- **Observability**: Prometheus metrics + OpenTelemetry (metrics/spans)
- **CLI tools**
  - `tcd-verify` — verify a single receipt or a chain
  - `tcd-replay` — replay JSONL/synthetic traffic to `/diagnose` with latency summary
- **gRPC (optional)**: mirrored semantics via protobuf shim
- **Storage helpers (optional)**: SQLite / in-memory ledgers & receipt stores

> **Why anytime-valid**: alpha-investing updates an e-process to control false discoveries **online** without a fixed horizon.


## Repository layout

.
├── Dockerfile
├── Makefile
├── deploy/helm/                        # Helm chart
├── ops/alerts/prometheus-rules.yaml
├── tcd/
│   ├── init.py
│   ├── service_http.py                 # FastAPI app (primary entry)
│   ├── service_grpc.py                 # gRPC shim (optional)
│   ├── admin_http.py                   # admin-only handlers (optional)
│   ├── cli/
│   │   ├── serve_http.py               # uvicorn runner
│   │   ├── verify.py                   # receipt/chain verification
│   │   └── replay.py                   # traffic replay
│   ├── api/proto/tcd.proto             # protobuf source
│   ├── ledger.py                       # alpha wealth & receipts (SQLite/mem)
│   ├── storage.py                      # generic stores
│   ├── exporter.py, otel_exporter.py, ratelimit.py, routing.py, …
│   ├── detector.py, risk_av.py, multivariate.py, signals.py, …
│   └── verify.py                       # verify_chain / verify_receipt
└── tests/property/


## Quick start

### Run HTTP sidecar (Python)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m tcd.cli.serve_http --host 0.0.0.0 --port 8080
# Swagger UI (if enabled by FastAPI): http://127.0.0.1:8080/docs

Or run with Docker

docker build -t tcd-sidecar .
docker run --rm -p 8080:8080 \
  -e TCD_RECEIPTS_ENABLE=1 \
  -e TCD_HASH_ALG=blake3 \
  tcd-sidecar

Send a sample /diagnose

curl -s http://127.0.0.1:8080/diagnose \
  -H 'content-type: application/json' \
  -d '{
    "trace_vector":[0.1,0.2,0.3],
    "spectrum":[0.01,0.02],
    "entropy":1.2,
    "features":[0.5,0.4],
    "model_id":"model0","gpu_id":"gpu0","task":"chat","lang":"en",
    "tenant":"t0","user":"u0","session":"s0",
    "context":{"temperature":0.7,"top_p":0.9},
    "tokens_delta":50,
    "drift_score":0.0
  }' | jq .

Example RiskResponse:

{
  "verdict": false,
  "score": 0.12,
  "threshold": 0.0,
  "budget_remaining": 0.05,
  "components": { "...": {} },
  "cause": "",
  "action": "none",
  "step": 3,
  "e_value": 1.0,
  "alpha_alloc": 0.0,
  "alpha_spent": 0.0,
  "receipt": "hex...",
  "receipt_body": "{...canonical JSON...}",
  "receipt_sig": "ed25519...",
  "verify_key": "ed25519..."
}


HTTP API

Endpoints
	•	GET /healthz → {"ok":true,"config_hash":"...","otel":bool,"prom":true,"receipts":bool}
	•	GET /version → version/config summary (alpha, slo_latency_ms, etc.)
	•	GET /state/get?model_id=&gpu_id=&task=&lang= → detector snapshot
	•	POST /state/load → { "state": { ... } } (load detector state)
	•	POST /diagnose → core decision endpoint
	•	POST /verify → verify a single receipt or a chain

Field caps & sanitization enforced. Invalid payload → HTTP 400, throttled → HTTP 429.

Models

DiagnoseRequest

Field	Type	Required	Notes
trace_vector	number[]	yes	bounded length
spectrum	number[]	no	bounded length
entropy	number	no	optional
features	number[]	no	aux only
step_id	integer	no	optional
model_id, gpu_id, task, lang	string	yes	routing keys
tenant, user, session	string	yes	rate-limit keys
context	object	no	e.g. { "temperature": 0.7, "top_p": 0.9 }
tokens_delta	integer	no	cost hint
drift_score	number	no	modulates thresholds

RiskResponse (core)

Field	Type	Notes
verdict	boolean	detector_trigger OR av_trigger
score, threshold	number	detector side
budget_remaining	number	alpha wealth
components	object	detector internals (JSON)
cause	string	`“detector”
action	string	"degrade" or "none"
step	integer	streaming step id
e_value, alpha_alloc, alpha_spent	number	AV process
receipt, receipt_body, receipt_sig, verify_key	string	present when receipts enabled

VerifyRequest

Single receipt:

{
  "receipt_head_hex": "hex",
  "receipt_body_json": { "..." : "..." },
  "verify_key_hex": "hex",
  "receipt_sig_hex": "hex",
  "req_obj": { },
  "comp_obj": { },
  "e_obj": { },
  "witness_segments": []
}

Chain verification:

{
  "heads": ["hex1","hex2","hex3"],
  "bodies": [{}, {}, {}]
}

VerifyResponse

{ "ok": true }


Verifiable receipts

Enable issuance:

export TCD_RECEIPTS_ENABLE=1
export TCD_HASH_ALG=blake3   # default shown; others if supported

When enabled, /diagnose returns a triplet:
	•	receipt (head, hex digest)
	•	receipt_body (canonical JSON: UTF-8, sorted keys, no extra whitespace)
	•	receipt_sig (optional Ed25519 signature) and verify_key (optional Ed25519 public key)

Verify a single receipt via HTTP POST /verify or the CLI:

python -m tcd.cli.verify receipt \
  --head "$(cat head.hex)" \
  --body "$(cat body.json)" \
  --vk "$(cat vk.hex)" \
  --sig "$(cat sig.hex)" \
  --json

Verify a chain (JSONL each line {"receipt":"...","receipt_body":"..."}):

python -m tcd.cli.verify chain --jsonl --heads receipts.jsonl --json


Rate limiting & always-valid control
	•	Rate limiting: token bucket per (tenant, user, session) using tokens_delta as cost hint; on throttle returns HTTP 429.
	•	Always-valid (AV): maps detector score → p-value proxy and updates the e-process/alpha wealth online. Decision rule:

verdict = detector_trigger OR av_trigger

Policies are configurable; validate on your datasets.


Observability
	•	Prometheus: built-in exporter; example alert rules at ops/alerts/prometheus-rules.yaml.
	•	OpenTelemetry: exporter pushes metrics/spans when enabled (OTLP HTTP).

Example metric names (may vary):

Metric	Type	Labels
tcd_requests_total	counter	endpoint, code
tcd_decisions_total	counter	verdict, cause
tcd_latency_ms	histogram	endpoint
tcd_alpha_wealth	gauge	tenant,user,session
tcd_rate_limited_total	counter	tenant


gRPC (optional)

Generate Python stubs (requires grpcio-tools):

python -m pip install grpcio grpcio-tools
python -m grpc_tools.protoc \
  -I tcd/api/proto \
  --python_out=tcd/proto \
  --grpc_python_out=tcd/proto \
  tcd/api/proto/tcd.proto
touch tcd/proto/__init__.py

Register services:

from concurrent import futures
import grpc
from tcd.service_grpc import register_grpc_services

server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
ok = register_grpc_services(server)  # False if stubs missing
if not ok:
    raise RuntimeError("Generate gRPC stubs from tcd/api/proto/tcd.proto.")
server.add_insecure_port("0.0.0.0:9090")
server.start()
server.wait_for_termination()


CLI tools

tcd-verify

Single receipt:

python -m tcd.cli.verify receipt \
  --head @head.hex \
  --body @body.json \
  --vk @vk.hex \
  --sig @sig.hex \
  --json

Chain (JSONL):

python -m tcd.cli.verify chain --jsonl --heads receipts.jsonl --json

tcd-replay

Synthetic:

python -m tcd.cli.replay --synthetic --count 256 --concurrency 8 --verify --json

Replay JSONL (one DiagnoseRequest per line):

python -m tcd.cli.replay --jsonl requests.jsonl --concurrency 8 --verify

Both CLIs can export Prometheus/OTel metrics (see --help).


Helm & Kubernetes

Minimal values.yaml:

image:
  repository: ghcr.io/yourorg/tcd-sidecar
  tag: v0.1.0
env:
  TCD_RECEIPTS_ENABLE: "1"
  TCD_HASH_ALG: "blake3"
  TCD_OTEL_ENDPOINT: "http://otel-collector:4318"
resources:
  requests: { cpu: "100m", memory: "256Mi" }
  limits:   { cpu: "1",    memory: "1Gi" }
service:
  port: 8080
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"

The chart lives under deploy/helm/.


Storage helpers (optional)

tcd/ledger.py, tcd/storage.py provide SQLite / in-memory implementations:

Component	Purpose	Notes
Alpha wealth ledger	track per-subject wealth	idempotent apply via idem keys
Receipt store	append / latest / walk / integrity	optional durable chain storage

The HTTP service does not require durable storage by default.


Configuration

Settings are env-driven via tcd.config.make_reloadable_settings().

Key	Type	Default	Example	Description
TCD_RECEIPTS_ENABLE	bool	0	1	enable inlined receipts
TCD_HASH_ALG	enum	blake3	blake3	digest for receipt head
TCD_OTEL_ENDPOINT	URL	""	http://otel:4318	OTLP HTTP endpoint
TCD_PROM_ENABLE	bool	1	1	Prometheus exporter on /metrics
TCD_PORT	int	8080	8080	HTTP port
TCD_RATE_LIMIT	bool	1	1	enable token bucket
TCD_BUCKET_RATE	float	1.0	5.0	tokens/sec
TCD_BUCKET_BURST	int	50	200	burst capacity
TCD_ALPHA_INIT	float	0.05	0.1	initial alpha wealth
TCD_SLO_LATENCY_MS	int	500	250	diagnose latency SLO

Check tcd/config.py for the full list of toggles and effective defaults.


Development

# Run HTTP server
python -m tcd.cli.serve_http --host 0.0.0.0 --port 8080

# Verify receipts
python -m tcd.cli.verify --help

# Replay traffic
python -m tcd.cli.replay --help

# Build container
docker build -t tcd-sidecar .


Security & notes
	•	Detector thresholds and AV policies are configurable; validate on your datasets.
	•	Receipts provide verifiable traceability, not a legal compliance guarantee.
	•	Arrays/payload sizes are sanitized and bounded; misuse → HTTP 400/429.


License

Apache-2.0 (see LICENSE).
