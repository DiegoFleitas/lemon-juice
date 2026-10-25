#!/usr/bin/env python3
"""NeMo Guardrails "self check input" runner for bench/nvidia-guardrails.

For every row of ``bench/nvidia-guardrails/inputs/inputs.jsonl`` this script makes
one ``rails.generate_async(messages=[{"role": "user", "content": text}])`` call
against the pinned local llama.cpp router and records a JSON row with the
block decision, the raw self-check completion, wall time, per-LLM-call
durations/tokens, and config/prompt hashes.

Design constraints (see bench/nvidia-guardrails ticket):
  * local endpoint only (http://127.0.0.1:9931); NVIDIA usage telemetry is
    disabled before importing NeMo Guardrails;
  * resumable: existing rows are matched by input sha256 and skipped, so a
    rerun never duplicates or rewrites recorded rows;
  * one row per input row, in input order, flushed per line;
  * the model is warmed up once before any timed case;
  * ``rails.explain().llm_calls`` accumulates across ``generate_async`` calls,
    so only the calls appended by the current case are recorded.

Usage (from anywhere; paths default to this file's bench directory):

    py bench/nvidia-guardrails/guardrail_runner.py
    py bench/nvidia-guardrails/guardrail_runner.py --limit 3 --out-dir <tmp>
    py bench/nvidia-guardrails/guardrail_runner.py --repeat-check

Requires ``PYTHONPATH`` to point at the directory holding nemoguardrails/openai
(see bench/nvidia-guardrails/requirements.txt); nothing is installed here.
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

# --- Environment hygiene, before importing anything that can open sockets ----
# 1) Never talk to any hosted endpoint: pin proxy handling so the local router
#    is reached directly even if the shell has proxy variables set.
os.environ["NO_PROXY"] = "127.0.0.1,localhost,::1"
os.environ["no_proxy"] = "127.0.0.1,localhost,::1"
# 2) NeMo Guardrails 0.24.1 reports anonymous usage stats to NVIDIA unless this
#    is set. The bench must not make any network call other than the local LLM.
os.environ["NEMO_GUARDRAILS_NO_USAGE_STATS"] = "1"
# 3) Local router authentication. If the operator started llama.cpp with
#    --api-key (recommended, see README), export the same key as LLAMA_API_KEY
#    and it is forwarded as the OpenAI-compatible bearer token. Only this
#    local-specific variable is honoured; ambient OpenAI/NVIDIA keys are dropped
#    so the runner can never authenticate to a hosted service. The key is never
#    logged or written to results.
LOCAL_API_KEY = os.environ.get("LLAMA_API_KEY", "").strip()
for _key_var in ("OPENAI_API_KEY", "NVIDIA_API_KEY"):
    os.environ.pop(_key_var, None)
if LOCAL_API_KEY:
    os.environ["OPENAI_API_KEY"] = LOCAL_API_KEY

from nemoguardrails import LLMRails, RailsConfig  # noqa: E402

# Console safety: case ids/decisions can contain arbitrary Unicode; make the
# progress log UTF-8 so a redirected shell pipe can never kill a run mid-way.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-standard streams
        pass

# ---------------------------------------------------------------------------
BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parents[1]
WORKSPACE_ROOT = REPO_ROOT.parent
CONFIG_DIR = BENCH_DIR / "config"
DEFAULT_INPUTS = BENCH_DIR / "inputs" / "inputs.jsonl"
DEFAULT_OUT_DIR = BENCH_DIR / "results" / "raw" / "2026-10-25-nemo-selfcheck-gemma3-4b"
MANIFEST_PATH = BENCH_DIR / "inputs" / "manifest.json"

RUNNER_VERSION = "1.0.2"
MODEL_ID = "ggml-org/gemma-3-4b-it-GGUF:Q4_K_M"
ENGINE = "openai"
BASE_URL = "http://127.0.0.1:9931"  # local llama.cpp router only
REFUSAL = "I'm sorry, I can't respond to that."
INTERNAL_ERROR = "I'm sorry, an internal error has occurred."
WARMUP_TEXT = "Hello! Can you help me with a question about my order?"
MAX_RETRIES = 2  # extra attempts after the first try
RETRY_DELAY_S = 2.0
REPEAT_CHECK_CASES = 6


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_HOME_RE = re.compile(r"[A-Za-z]:\\Users\\[^\\\s\"']+", re.IGNORECASE)


def sanitize(text, limit=500) -> str:
    """Keep error/log strings free of absolute user paths before they land in
    committed result files."""
    s = str(text)
    s = s.replace(str(WORKSPACE_ROOT), "<workspace>").replace(str(REPO_ROOT), "<repo>")
    s = _HOME_RE.sub("<home>", s)
    s = s.replace("\\", "/")
    s = s.replace("\n", " ").replace("\r", " ")
    return s[:limit]


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def truncate(value, limit=200):
    if value is None:
        return None
    s = str(value)
    return s if len(s) <= limit else s[:limit]


def rel(path: Path) -> str:
    """Repo- or workspace-relative display path (never absolute)."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        try:
            return path.resolve().relative_to(WORKSPACE_ROOT).as_posix()
        except ValueError:
            return path.name


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------
def load_inputs(path: Path):
    rows = []
    seen = set()
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            for key in ("id", "text", "sha256", "track", "label"):
                if key not in row:
                    raise SystemExit(f"inputs.jsonl line {lineno}: missing field {key!r}")
            if row["id"] in seen:
                raise SystemExit(f"inputs.jsonl line {lineno}: duplicate id {row['id']!r}")
            seen.add(row["id"])
            actual = sha256_text(row["text"])
            if actual != row["sha256"]:
                raise SystemExit(
                    f"inputs.jsonl line {lineno}: sha256 mismatch for id {row['id']!r} ({actual} != {row['sha256']})"
                )
            rows.append(row)
    if not rows:
        raise SystemExit(f"no cases found in {path}")
    return rows


def load_existing(out_dir: Path):
    """Return (rows_by_id, ordered_rows) from an existing guardrail.jsonl."""
    path = out_dir / "guardrail.jsonl"
    by_id = {}
    ordered = []
    if not path.exists():
        return by_id, ordered
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit(f"{rel(path)} line {lineno} is not valid JSON: {e}")
            if "id" not in row:
                raise SystemExit(f"{rel(path)} line {lineno}: no id")
            if row["id"] in by_id:
                note = "" if by_id[row["id"]].get("input_sha256") == row.get("input_sha256") else " (conflicting hashes)"
                raise SystemExit(f"{rel(path)} line {lineno}: duplicate id {row['id']!r}{note}")
            by_id[row["id"]] = row
            ordered.append(row)
    return by_id, ordered


# ---------------------------------------------------------------------------
# LLM call extraction
# ---------------------------------------------------------------------------
def _call_to_dict(call) -> dict:
    return {
        "task": call.task,
        "duration": round(float(call.duration), 4) if call.duration is not None else None,
        "prompt_tokens": call.prompt_tokens,
        "completion_tokens": call.completion_tokens,
        "total_tokens": call.total_tokens,
        "completion": truncate(call.completion, 200),
    }


def extract_self_check(calls):
    """Return (decision_raw_stripped_or_None, raw_full_or_None) from the case's
    self_check_input LLM call(s)."""
    self_checks = [c for c in calls if (c.task or "").startswith("self_check_input")]
    if not self_checks:
        return None, None
    raw = self_checks[-1].completion or ""
    return raw.strip(), raw


def normalize_decision(decision):
    if decision is None:
        return None
    token = decision.strip().strip(".").strip().lower()
    if token.startswith("yes"):
        return "Yes"
    if token.startswith("no"):
        return "No"
    return "other"


def response_content(res) -> str:
    if isinstance(res, dict):
        content = res.get("content")
        if content is None:
            messages = res.get("messages") or []
            content = "\n".join(str(m) for m in messages)
        return "" if content is None else str(content)
    return "" if res is None else str(res)


def build_row(case, res, gr_ms, calls, config_sha, prompts_sha, error=None, attempts=1):
    content = response_content(res) if res is not None else ""
    stripped = content.strip()
    blocked = stripped == REFUSAL
    if error is None and stripped == INTERNAL_ERROR:
        error = "internal_error_message"
    if error is not None and res is None:
        blocked = None
    decision, raw = extract_self_check(calls)
    return {
        "id": case["id"],
        "track": case.get("track"),
        "input_sha256": sha256_text(case["text"]),
        "label": case.get("label"),
        "family": case.get("family", ""),
        "split": case.get("split", ""),
        "blocked": blocked,
        "decision": truncate(decision, 500),
        "decision_normalized": normalize_decision(decision),
        "self_check_raw": truncate(raw, 500),
        "response": truncate(content, 200),
        "gr_ms": int(round(gr_ms)),
        "llm_calls": [_call_to_dict(c) for c in calls],
        "config_sha256": config_sha,
        "prompts_sha256": prompts_sha,
        "model": MODEL_ID,
        "attempts": attempts,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
def build_meta(tag, inputs_path, out_dir, inputs, rows, config_sha, prompts_sha, started_at, finished_at, warmup_s, status, repeat_check=None):
    by_track = Counter(r["track"] for r in rows)
    by_label = Counter(r["label"] for r in rows)
    by_family = Counter(r.get("family", "") for r in rows)
    blocked_by_track = Counter(r["track"] for r in rows if r.get("blocked") is True)
    blocked_by_label = Counter(r["label"] for r in rows if r.get("blocked") is True)
    blocked_by_family = Counter(r.get("family", "") for r in rows if r.get("blocked") is True)
    error_ids = [r["id"] for r in rows if r.get("error")]
    attempts_hist = Counter(int(r.get("attempts") or 1) for r in rows)
    total_tokens = sum(
        (c.get("total_tokens") or 0) for r in rows for c in (r.get("llm_calls") or [])
    )

    manifest_sha = None
    manifest_cases = None
    manifest_by_track = None
    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        manifest_sha = manifest.get("sha256")
        manifest_cases = manifest.get("cases")
        manifest_by_track = manifest.get("by_track")

    return {
        "tag": tag,
        "runner_version": RUNNER_VERSION,
        "status": status,
        "rail": "self check input",
        "engine": ENGINE,
        "model": MODEL_ID,
        "base_url_note": (
            "http://127.0.0.1:9931 (local llama.cpp OpenAI-compatible router); "
            "no hosted/network endpoint was called"
            + (
                "; the local bearer key from LLAMA_API_KEY was used"
                if LOCAL_API_KEY
                else "; no credential was used"
            )
        ),
        "local_api_key_configured": bool(LOCAL_API_KEY),
        "telemetry_note": "NeMo Guardrails usage reporting disabled (NEMO_GUARDRAILS_NO_USAGE_STATS=1)",
        "config_dir": rel(CONFIG_DIR),
        "inputs_path": rel(inputs_path),
        "raw_path": rel(out_dir / "guardrail.jsonl"),
        "repeat_check_path": rel(out_dir / "repeat-check.jsonl") if (out_dir / "repeat-check.jsonl").exists() else None,
        "config_sha256": config_sha,
        "prompts_sha256": prompts_sha,
        "inputs_sha256": sha256_file(inputs_path),
        "inputs_manifest_sha256": manifest_sha,
        "case_count": len(rows),
        "input_case_count": len(inputs),
        "manifest_case_count": manifest_cases,
        "by_track": dict(sorted(by_track.items())),
        "by_label": dict(sorted(by_label.items())),
        "by_family": dict(sorted(by_family.items())),
        "blocked_total": sum(1 for r in rows if r.get("blocked") is True),
        "blocked_by_track": dict(sorted(blocked_by_track.items())),
        "blocked_by_label": dict(sorted(blocked_by_label.items())),
        "blocked_by_family": dict(sorted(blocked_by_family.items())),
        "errors": {"count": len(error_ids), "ids": error_ids},
        "attempts_histogram": {str(k): v for k, v in sorted(attempts_hist.items())},
        "llm_calls_total": sum(len(r.get("llm_calls") or []) for r in rows),
        "tokens_total": total_tokens,
        "warmup_seconds": round(warmup_s, 3) if warmup_s is not None else None,
        "started_at": started_at,
        "finished_at": finished_at,
        "wall_seconds": (
            round(
                (datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds(), 1
            )
            if finished_at
            else None
        ),
        "versions": {
            "python": ".".join(map(str, sys.version_info[:3])),
            "nemoguardrails": _dist_version("nemoguardrails"),
            "openai": _dist_version("openai"),
        },
        "repeat_check": repeat_check,
        "resume_note": (
            "Existing rows are skipped by id + input sha256; a rerun appends only missing ids "
            "and never rewrites or duplicates recorded rows."
        ),
    }


def _dist_version(name: str):
    try:
        from importlib.metadata import version

        return version(name)
    except Exception:  # pragma: no cover - metadata optional
        return None


def write_json_atomic(path: Path, payload) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
class CaseError(Exception):
    pass


async def generate_case(rails, case, config_sha, prompts_sha):
    """Run one case with retries. Returns (row, retried_ok)."""
    last_error = None
    for attempt in range(1, MAX_RETRIES + 2):
        n_before = len(rails.explain().llm_calls)
        t0 = time.perf_counter()
        try:
            res = await rails.generate_async(messages=[{"role": "user", "content": case["text"]}])
        except Exception as exc:  # noqa: BLE001 - per-case errors must not kill the run
            gr_ms = (time.perf_counter() - t0) * 1000.0
            last_error = sanitize(f"{type(exc).__name__}: {exc}")
            if attempt <= MAX_RETRIES:
                await asyncio.sleep(RETRY_DELAY_S)
                continue
            calls = list(rails.explain().llm_calls[n_before:])
            row = build_row(case, None, gr_ms, calls, config_sha, prompts_sha, error=last_error, attempts=attempt)
            return row, attempt > 1
        gr_ms = (time.perf_counter() - t0) * 1000.0
        calls = list(rails.explain().llm_calls[n_before:])
        row = build_row(case, res, gr_ms, calls, config_sha, prompts_sha, attempts=attempt)
        if row["error"] is None:
            return row, attempt > 1
        last_error = row["error"]
        if attempt <= MAX_RETRIES:
            await asyncio.sleep(RETRY_DELAY_S)
            continue
        row["attempts"] = attempt
        return row, attempt > 1
    raise CaseError(last_error or "unreachable")


def resolve_repeat_ids(inputs):
    n = len(inputs)
    if n <= REPEAT_CHECK_CASES:
        return [row["id"] for row in inputs]
    idx = sorted({round(i * (n - 1) / (REPEAT_CHECK_CASES - 1)) for i in range(REPEAT_CHECK_CASES)})
    return [inputs[i]["id"] for i in idx]


async def run_main(args, inputs, out_dir, started_at):
    config_sha = sha256_file(CONFIG_DIR / "config.yml")
    prompts_sha = sha256_file(CONFIG_DIR / "prompts.yml")

    existing, _ = load_existing(out_dir)
    # every pre-existing row must belong to a current input with the same hash
    known = {row["id"]: sha256_text(row["text"]) for row in inputs}
    for row_id, row in existing.items():
        if row_id not in known:
            raise SystemExit(f"existing row id {row_id!r} is not in the current inputs; refusing to mix")
        if row.get("input_sha256") != known[row_id]:
            raise SystemExit(f"existing row id {row_id!r} has a stale input sha256; refusing to mix")

    if args.ids:
        wanted = [i.strip() for i in args.ids.split(",") if i.strip()]
        by_id = {row["id"]: row for row in inputs}
        unknown = [i for i in wanted if i not in by_id]
        if unknown:
            raise SystemExit(f"unknown --ids: {unknown}")
        selected = [row for row in inputs if row["id"] in set(wanted)]
    else:
        selected = list(inputs)
    if args.limit is not None:
        selected = selected[: max(args.limit, 0)]

    pending = [row for row in selected if row["id"] not in existing]

    print(
        f"[nemo] cases in inputs={len(inputs)} selected={len(selected)} "
        f"already_recorded={len(selected) - len(pending)} pending={len(pending)}",
        flush=True,
    )
    print(f"[nemo] config={rel(CONFIG_DIR)} config_sha256={config_sha[:12]} prompts_sha256={prompts_sha[:12]}", flush=True)

    # Idempotent resume: when everything selected is already recorded, leave the
    # raw file AND meta.json byte-for-byte untouched (only backfill meta if absent).
    if not pending:
        if not (out_dir / "meta.json").exists() and existing:
            order = {row["id"]: pos for pos, row in enumerate(inputs)}
            recorded_sorted = sorted(existing.values(), key=lambda r: order[r["id"]])
            meta = build_meta(
                tag=out_dir.name,
                inputs_path=args.inputs,
                out_dir=out_dir,
                inputs=inputs,
                rows=recorded_sorted,
                config_sha=config_sha,
                prompts_sha=prompts_sha,
                started_at=started_at,
                finished_at=now_iso(),
                warmup_s=None,
                status="complete" if len(recorded_sorted) == len(inputs) else "partial",
            )
            write_json_atomic(out_dir / "meta.json", meta)
        print(
            "[nemo] nothing to do: all selected cases already recorded; "
            "guardrail.jsonl and meta.json left untouched",
            flush=True,
        )
        return

    config = RailsConfig.from_path(str(CONFIG_DIR))
    rails = LLMRails(config)

    # Warm the model/runtime once, outside of any timed case.
    warm_t0 = time.perf_counter()
    try:
        await rails.generate_async(messages=[{"role": "user", "content": WARMUP_TEXT}])
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"warmup failed, model/router not usable: {sanitize(f'{type(exc).__name__}: {exc}')}")
    warmup_s = time.perf_counter() - warm_t0
    print(f"[nemo] warmup ok in {warmup_s:.2f}s", flush=True)

    raw_path = out_dir / "guardrail.jsonl"
    retried = []
    written = 0
    t_all = time.perf_counter()
    with open(raw_path, "a", encoding="utf-8", newline="\n") as raw_file:
        for i, case in enumerate(pending, 1):
            row, retried_ok = await generate_case(rails, case, config_sha, prompts_sha)
            raw_file.write(json.dumps(row, ensure_ascii=False) + "\n")
            raw_file.flush()
            written += 1
            if row["attempts"] > 1:
                retried.append({"id": row["id"], "attempts": row["attempts"], "error": row["error"]})
            elapsed = time.perf_counter() - t_all
            eta = elapsed / i * (len(pending) - i)
            print(
                f"[nemo] {i}/{len(pending)} id={row['id']} track={row['track']} "
                f"blocked={row['blocked']} decision={row['decision_normalized']} "
                f"raw={truncate(row['decision'], 40)!r} gr_ms={row['gr_ms']} "
                f"calls={len(row['llm_calls'])} err={row['error']} eta={eta:.0f}s",
                flush=True,
            )

    # Re-read everything from disk so meta reflects exactly what is recorded.
    _, recorded = load_existing(out_dir)
    order = {row["id"]: pos for pos, row in enumerate(inputs)}
    recorded_sorted = sorted(recorded, key=lambda r: order[r["id"]])

    # Merge per-run retry info into meta only (raw rows already carry attempts).
    all_pending_ok = all(r.get("error") is None for r in recorded_sorted)
    meta = build_meta(
        tag=out_dir.name,
        inputs_path=args.inputs,
        out_dir=out_dir,
        inputs=inputs,
        rows=recorded_sorted,
        config_sha=config_sha,
        prompts_sha=prompts_sha,
        started_at=started_at,
        finished_at=now_iso(),
        warmup_s=warmup_s,
        status="complete" if len(recorded_sorted) == len(inputs) and all_pending_ok else "partial",
    )
    if retried:
        meta["retried_cases"] = retried
    write_json_atomic(out_dir / "meta.json", meta)

    print(
        f"[nemo] done: new_rows={written} total_rows={len(recorded_sorted)}/{len(inputs)} "
        f"errors={meta['errors']['count']} wall={time.perf_counter() - t_all:.1f}s",
        flush=True,
    )
    return rails, config_sha, prompts_sha


async def run_repeat_check(args, inputs, out_dir, started_at):
    existing, _ = load_existing(out_dir)
    if not existing:
        raise SystemExit("--repeat-check needs an existing guardrail.jsonl; run the main pass first")
    repeat_ids = resolve_repeat_ids(inputs)
    by_id = {row["id"]: row for row in inputs}
    config = RailsConfig.from_path(str(CONFIG_DIR))
    rails = LLMRails(config)
    config_sha = sha256_file(CONFIG_DIR / "config.yml")
    prompts_sha = sha256_file(CONFIG_DIR / "prompts.yml")

    warm_t0 = time.perf_counter()
    try:
        await rails.generate_async(messages=[{"role": "user", "content": WARMUP_TEXT}])
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"warmup failed, model/router not usable: {sanitize(f'{type(exc).__name__}: {exc}')}")
    warmup_s = time.perf_counter() - warm_t0
    print(f"[nemo] repeat-check warmup ok in {warmup_s:.2f}s for {len(repeat_ids)} cases", flush=True)

    repeat_path = out_dir / "repeat-check.jsonl"
    rows = []
    t_repeat = time.perf_counter()
    with open(repeat_path, "w", encoding="utf-8", newline="\n") as f:
        for case_id in repeat_ids:
            case = by_id[case_id]
            row, _ = await generate_case(rails, case, config_sha, prompts_sha)
            row["pass"] = "repeat"
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            f.flush()
            rows.append(row)
            print(
                f"[nemo] repeat {case_id} blocked={row['blocked']} "
                f"decision={row['decision_normalized']} raw={truncate(row['decision'], 40)!r} "
                f"gr_ms={row['gr_ms']} err={row['error']}",
                flush=True,
            )

    per_case = []
    for row in rows:
        first = existing[row["id"]]
        per_case.append(
            {
                "id": row["id"],
                "first": {"blocked": first.get("blocked"), "decision": first.get("decision")},
                "second": {"blocked": row.get("blocked"), "decision": row.get("decision")},
                "blocked_match": first.get("blocked") == row.get("blocked"),
                "decision_match": first.get("decision") == row.get("decision"),
                "input_sha_match": first.get("input_sha256") == row.get("input_sha256"),
            }
        )
    repeat = {
        "ids": repeat_ids,
        "selection": "6 ids at evenly spaced positions across inputs.jsonl order (deterministic)",
        "cases": len(rows),
        "started_at": started_at,
        "finished_at": now_iso(),
        "wall_seconds": round((time.perf_counter() - t_repeat), 1),
        "warmup_seconds": round(warmup_s, 3),
        "blocked_stable": all(c["blocked_match"] for c in per_case),
        "decision_stable": all(c["decision_match"] for c in per_case),
        "input_hashes_match": all(c["input_sha_match"] for c in per_case),
        "stable": all(c["blocked_match"] and c["decision_match"] and c["input_sha_match"] for c in per_case),
        "per_case": per_case,
    }

    _, recorded = load_existing(out_dir)
    order = {row["id"]: pos for pos, row in enumerate(inputs)}
    recorded_sorted = sorted(recorded, key=lambda r: order[r["id"]])
    prior_meta = {}
    prior_path = out_dir / "meta.json"
    if prior_path.exists():
        try:
            prior_meta = json.loads(prior_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prior_meta = {}
    meta = build_meta(
        tag=out_dir.name,
        inputs_path=args.inputs,
        out_dir=out_dir,
        inputs=inputs,
        rows=recorded_sorted,
        config_sha=config_sha,
        prompts_sha=prompts_sha,
        started_at=prior_meta.get("started_at", started_at),
        finished_at=prior_meta.get("finished_at", now_iso()),
        warmup_s=prior_meta.get("warmup_seconds", warmup_s),
        status="complete" if len(recorded_sorted) == len(inputs) else "partial",
        repeat_check=repeat,
    )
    write_json_atomic(out_dir / "meta.json", meta)
    print(
        f"[nemo] repeat-check done: stable={repeat['stable']} "
        f"decision_stable={repeat['decision_stable']} blocked_stable={repeat['blocked_stable']}",
        flush=True,
    )


async def amain(args):
    args.inputs = Path(args.inputs).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.force:
        for name in ("guardrail.jsonl", "repeat-check.jsonl", "meta.json"):
            target = out_dir / name
            if target.exists():
                target.unlink()
        print(f"[nemo] --force: cleared raw files in {rel(out_dir)}", flush=True)

    # Ad-hoc smoke runs may write anywhere in the workspace; the committed run
    # uses the default results/raw/<tag> directory.
    inputs = load_inputs(args.inputs)
    started_at = now_iso()

    if args.repeat_check:
        await run_repeat_check(args, inputs, out_dir, started_at)
    else:
        await run_main(args, inputs, out_dir, started_at)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Run the NeMo Guardrails 0.24.1 'self check input' rail over "
            "bench/nvidia-guardrails/inputs/inputs.jsonl against the local llama.cpp router."
        )
    )
    parser.add_argument("--inputs", default=str(DEFAULT_INPUTS), help="inputs JSONL (default: bench/nvidia-guardrails/inputs/inputs.jsonl)")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help="raw results directory (default: results/raw/2026-10-25-nemo-selfcheck-gemma3-4b)")
    parser.add_argument("--limit", type=int, default=None, help="only consider the first N selected cases (smoke runs)")
    parser.add_argument("--ids", default=None, help="comma-separated case ids to run (smoke runs)")
    parser.add_argument("--force", action="store_true", help="delete guardrail.jsonl/repeat-check.jsonl/meta.json in --out-dir first")
    parser.add_argument("--repeat-check", action="store_true", help="rerun a deterministic sample of 6 recorded cases into repeat-check.jsonl")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    asyncio.run(amain(args))


if __name__ == "__main__":
    main()
