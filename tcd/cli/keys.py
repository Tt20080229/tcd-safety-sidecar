from __future__ import annotations

"""
tcd-keys — Key & salt lifecycle toolkit for the TCD verifiable pipeline.

Why this exists
  - Manage Ed25519 attestation keys (generate, rotate, print).
  - Manage label salts used for domain-separated BLAKE3 commitments.
  - Dry-run sign/verify against canonical JSON to sanity-check setup.
  - Optional Prom/OTel SRE signals for long-running ops.

Environment variables honored
  - TCD_ATTEST_SK_HEX         : Ed25519 secret key (hex; 64 bytes -> 128 hex chars).
  - TCD_LABEL_SALT_HEX        : Hex salt for label hashing & commitments (length flexible).
  - TCD_LABEL_SALT_VERSION    : Integer version for salt rotation (default "1").
  - TCD_KEYS_PROM_HTTP        : "1" to expose Prometheus /metrics for this CLI (off by default).
  - TCD_KEYS_PROM_PORT        : Port for Prometheus server (default 8030).
  - TCD_OTEL_ENDPOINT         : OTLP endpoint (default http://localhost:4318).

Security notes
  - Printing secret material to stdout is dangerous. By default we print to stdout because this is a CLI.
    Prefer redirecting to a protected file and/or using --exports for shell-friendly one-liners.
  - Rotations should be staged: generate new keys/salts, deploy verify key & salt version, roll writers,
    and only then deprecate old material (see `rotate` guidance).
"""

import json
import os
import sys
import time
from typing import Dict, Optional

import click
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey

from ..attest import Attestor
from ..exporter import TCDPrometheusExporter
from ..otel_exporter import TCDOtelExporter
from ..verify import verify_receipt


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() not in ("", "0", "false", "no")


PROM_HTTP_DEFAULT = _env_bool("TCD_KEYS_PROM_HTTP", False)
PROM_PORT_DEFAULT = int(os.environ.get("TCD_KEYS_PROM_PORT", "8030"))


def _mk_prom(prom_http: bool, port: int) -> TCDPrometheusExporter:
    prom = TCDPrometheusExporter(port=port, version="0.10.2", config_hash="cli-keys")
    if prom_http:
        prom.ensure_server()
    return prom


def _mk_otel() -> TCDOtelExporter:
    otel = TCDOtelExporter(endpoint=os.environ.get("TCD_OTEL_ENDPOINT", "http://localhost:4318"))
    return otel


def _now_ms() -> float:
    import time as _t

    return _t.perf_counter() * 1000.0


def _mask(s: str, keep: int = 8) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return s
    return f"{s[:keep]}…{s[-keep:]}"


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--prom-http/--no-prom-http", default=PROM_HTTP_DEFAULT, show_default=True, help="Expose Prometheus /metrics for this CLI run.")
@click.option("--prom-port", type=int, default=PROM_PORT_DEFAULT, show_default=True, help="Prometheus port if enabled.")
@click.pass_context
def cli(ctx: click.Context, prom_http: bool, prom_port: int):
    """TCD Keys — manage attestation keys and label salts for verifiable receipts."""
    ctx.ensure_object(dict)
    ctx.obj["prom"] = _mk_prom(prom_http, prom_port)
    ctx.obj["otel"] = _mk_otel()


# ------------------------------------ keypair ----------------------------------------


@cli.command("gen")
@click.option("--exports", is_flag=True, help="Print shell export lines for the generated secrets.")
@click.option("--json", "json_out", is_flag=True, help="Print JSON output instead of human text.")
@click.pass_context
def gen_cmd(ctx: click.Context, exports: bool, json_out: bool):
    """
    Generate a fresh Ed25519 keypair.

    Outputs:
      - secret (sk_hex)
      - verify key (vk_hex)
    """
    prom: TCDPrometheusExporter = ctx.obj["prom"]
    otel: TCDOtelExporter = ctx.obj["otel"]

    t0 = _now_ms()
    sk = SigningKey.generate()
    vk = sk.verify_key
    sk_hex = sk.encode(encoder=HexEncoder).decode()
    vk_hex = vk.encode(encoder=HexEncoder).decode()
    dur = (_now_ms() - t0) / 1000.0

    if json_out:
        print(json.dumps({"sk_hex": sk_hex, "vk_hex": vk_hex}, ensure_ascii=False, indent=2))
    elif exports:
        print(f'export TCD_ATTEST_SK_HEX="{sk_hex}"')
        print(f'# verify key (public) — safe to share/deploy to verifiers')
        print(f'export TCD_ATTEST_VK_HEX="{vk_hex}"')
    else:
        click.echo(f"[tcd-keys] generated Ed25519 keypair")
        click.echo(f"  sk_hex: {sk_hex}")
        click.echo(f"  vk_hex: {vk_hex}")

    prom.observe_latency(dur)
    otel.push_metrics(1.0, attrs={"op": "keys.gen"})


@cli.command("print")
@click.option("--json", "json_out", is_flag=True, help="Print JSON output.")
def print_cmd(json_out: bool):
    """
    Print current key/salt material from environment (masked).
    """
    sk_hex = os.environ.get("TCD_ATTEST_SK_HEX", "")
    vk_hex = ""
    if sk_hex:
        try:
            vk_hex = SigningKey(sk_hex, encoder=HexEncoder).verify_key.encode(encoder=HexEncoder).decode()
        except Exception:
            vk_hex = "(invalid SK)"

    salt_hex = os.environ.get("TCD_LABEL_SALT_HEX", "")
    salt_ver = os.environ.get("TCD_LABEL_SALT_VERSION", "1")

    out = {
        "sk_hex_masked": _mask(sk_hex),
        "vk_hex": vk_hex,
        "label_salt_hex_masked": _mask(salt_hex),
        "label_salt_version": salt_ver,
    }
    if json_out:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        click.echo("[tcd-keys] current environment")
        click.echo(f"  sk_hex: {out['sk_hex_masked']}")
        click.echo(f"  vk_hex: {vk_hex}")
        click.echo(f"  label_salt_hex: {out['label_salt_hex_masked']}")
        click.echo(f"  label_salt_version: {salt_ver}")


# ------------------------------------ salt -------------------------------------------


@cli.command("salt-gen")
@click.option("--bytes", "nbytes", type=int, default=32, show_default=True, help="Number of random bytes.")
@click.option("--version", default="1", show_default=True, help="Label salt version to use.")
@click.option("--exports", is_flag=True, help="Print shell export lines.")
@click.option("--json", "json_out", is_flag=True, help="Print JSON.")
def salt_gen_cmd(nbytes: int, version: str, exports: bool, json_out: bool):
    """
    Generate a random label salt (hex).
    """
    nbytes = max(8, min(128, int(nbytes)))
    salt_hex = os.urandom(nbytes).hex()
    if json_out:
        print(json.dumps({"label_salt_hex": salt_hex, "label_salt_version": version}, ensure_ascii=False, indent=2))
    elif exports:
        print(f'export TCD_LABEL_SALT_HEX="{salt_hex}"')
        print(f'export TCD_LABEL_SALT_VERSION="{version}"')
    else:
        click.echo("[tcd-keys] generated label salt")
        click.echo(f"  label_salt_hex: {salt_hex}")
        click.echo(f"  label_salt_version: {version}")


# ----------------------------------- rotate ------------------------------------------


@cli.command("rotate")
@click.option("--stage", type=click.Choice(["salt", "key", "both"]), default="both", show_default=True, help="What to rotate.")
@click.option("--salt-bytes", type=int, default=32, show_default=True, help="Salt length in bytes (for salt rotation).")
@click.option("--salt-version", default=None, help="Override label salt version (default: auto-increment if env present, else '1').")
@click.option("--exports", is_flag=True, help="Print shell export lines for staged rotation.")
@click.option("--json", "json_out", is_flag=True, help="Print JSON.")
def rotate_cmd(stage: str, salt_bytes: int, salt_version: Optional[str], exports: bool, json_out: bool):
    """
    Stage a rotation plan (does NOT mutate running services):
      1) Generate new salt (and version) and/or new keypair.
      2) Output what to deploy where:
         - Deploy verify key (public) & salt(version) to verifiers first.
         - Roll writers with new SK and same salt/version (or new version).
         - Optionally keep verifying old receipts using previously deployed salt/version.

    This CLI prints the staged material; operators then roll it out with standard tooling.
    """
    plan: Dict[str, str] = {}

    if stage in ("key", "both"):
        sk = SigningKey.generate()
        vk = sk.verify_key
        plan["new_sk_hex"] = sk.encode(encoder=HexEncoder).decode()
        plan["new_vk_hex"] = vk.encode(encoder=HexEncoder).decode()

    if stage in ("salt", "both"):
        salt_hex = os.urandom(max(8, min(128, int(salt_bytes)))).hex()
        old_ver = os.environ.get("TCD_LABEL_SALT_VERSION")
        if salt_version is None:
            if old_ver is not None and old_ver.isdigit():
                try:
                    salt_version = str(int(old_ver) + 1)
                except Exception:
                    salt_version = "1"
            else:
                salt_version = "1"
        plan["new_label_salt_hex"] = salt_hex
        plan["new_label_salt_version"] = str(salt_version)

    if json_out:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    elif exports:
        if "new_sk_hex" in plan:
            print(f'export TCD_ATTEST_SK_HEX="{plan["new_sk_hex"]}"')
            print(f'export TCD_ATTEST_VK_HEX="{plan["new_vk_hex"]}"  # distribute to verifiers')
        if "new_label_salt_hex" in plan:
            print(f'export TCD_LABEL_SALT_HEX="{plan["new_label_salt_hex"]}"')
            print(f'export TCD_LABEL_SALT_VERSION="{plan["new_label_salt_version"]}"')
    else:
        click.echo("[tcd-keys] staged rotation plan")
        for k, v in plan.items():
            click.echo(f"  {k}: {v}")

    # Guidance
    click.echo("\n[rollout guidance]")
    click.echo("  1) Deploy new verify key & label salt(+version) to verifiers and config maps.")
    click.echo("  2) Roll writers (sidecars) with NEW secret key and salt/version.")
    click.echo("  3) Keep the old verify material around long enough to audit legacy receipts.")
    click.echo("  4) Update dashboards/alerts to watch receipt chain continuity and verify failures.")


# ----------------------------------- sign/verify -------------------------------------


@cli.command("sign")
@click.option("--json-body", required=True, help="Canonical JSON body to sign (path, '-' or literal JSON).")
@click.option("--json", "json_out", is_flag=True, help="Print JSON.")
def sign_cmd(json_body: str, json_out: bool):
    """
    Sign a canonical JSON body with the current TCD_ATTEST_SK_HEX from environment.

    Outputs:
      - signature hex
      - derived verify key hex
    """
    body: Optional[str]
    if json_body == "-":
        body = sys.stdin.read()
    else:
        try:
            if os.path.exists(json_body):
                body = open(json_body, "r", encoding="utf-8").read()
            else:
                # treat as literal json text
                body = json_body
        except Exception as e:
            click.echo(f"read error: {e}", err=True)
            sys.exit(2)

    try:
        # ensure valid JSON; signer should always sign canonical
        json.loads(body or "{}")
    except Exception:
        click.echo("body is not valid JSON", err=True)
        sys.exit(2)

    sk_hex = os.environ.get("TCD_ATTEST_SK_HEX", "")
    if not sk_hex:
        click.echo("TCD_ATTEST_SK_HEX not set", err=True)
        sys.exit(2)

    try:
        sk = SigningKey(sk_hex, encoder=HexEncoder)
        vk_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
        sig_hex = sk.sign((body or "").encode("utf-8")).signature.hex()
    except Exception as e:
        click.echo(f"sign error: {e}", err=True)
        sys.exit(2)

    out = {"sig_hex": sig_hex, "verify_key_hex": vk_hex}
    if json_out:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        click.echo(f"[tcd-keys] signature: {sig_hex}")
        click.echo(f"verify key: {vk_hex}")


@cli.command("dry-run")
def dry_run_cmd():
    """
    End-to-end dry run: issue a minimal receipt (without witnesses) via Attestor
    using the current environment, then verify it. Useful for smoke tests.
    """
    # Prepare a tiny canonical body triplet
    req_obj = {"prompt_digest": "deadbeef"}
    comp_obj = {"decision": "OK", "policy_ref": "v1"}
    e_obj = {"e": 1.0}

    # Issue
    try:
        att = Attestor()
        rcpt = att.issue(
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=([1, 2, 3], [4, 5], [6]),  # integers packed into field elements
            witness_tags=("trace", "spectrum", "feat"),
            meta={"tool": "tcd-keys", "op": "dry-run"},
        )
    except Exception as e:
        click.echo(f"issue error: {e}", err=True)
        sys.exit(2)

    # Verify
    ok = verify_receipt(
        receipt_head_hex=rcpt["receipt"],
        receipt_body_json=rcpt["receipt_body"],
        verify_key_hex=(rcpt.get("verify_key") or None),
        receipt_sig_hex=(rcpt.get("receipt_sig") or None),
        req_obj=req_obj,
        comp_obj=comp_obj,
        e_obj=e_obj,
        witness_segments=([1, 2, 3], [4, 5], [6]),
        strict=True,
        label_salt_hex=os.environ.get("TCD_LABEL_SALT_HEX") or None,
    )
    status = "OK" if ok else "FAIL"
    click.echo(f"[tcd-keys] dry-run verify: {status}")

    # Pretty-print artifacts for operators
    click.echo(json.dumps({"receipt": rcpt["receipt"], "body": json.loads(rcpt["receipt_body"])}, ensure_ascii=False, indent=2))


# ----------------------------------- version -----------------------------------------


@cli.command("version")
def version_cmd():
    """Print tool version."""
    print(json.dumps({"tool": "tcd-keys", "version": "0.10.2"}, ensure_ascii=False))


def main():
    cli(standalone_mode=False)
    # click manages exit codes


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(2)
