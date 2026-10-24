"""Paired local inference trials plus exhaustive deterministic policy validation."""
from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
import platform
import sys
from pathlib import Path
from typing import Any

from avagelm.core.corpus import make_corpus, representative_cases, canonical_digest
from avagelm.core.provenance import PolicyGateway, Provenance, Trust
from avagelm.core.providers import make_provider
from avagelm.evaluators.judge import score
from avagelm.utils.audit import write_signed_audit
from avagelm.utils.visualizer import charts


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def run(out: Path, provider_name: str = "ollama", model: str = "llama3.2:latest", trials: int = 5,
        base_url: str | None = None, timeout: float = 300) -> dict[str, Any]:
    if type(trials) is not int or trials < 1:
        raise ValueError("trials must be a positive integer")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")
    out.mkdir(parents=True, exist_ok=True)
    corpus = make_corpus()
    corpus_hash = canonical_digest(corpus)
    corpus_path = out / "payloads.jsonl"
    corpus_path.write_text("\n".join(json.dumps(asdict(c), ensure_ascii=False) for c in corpus) + "\n", encoding="utf-8")
    gateway = PolicyGateway()

    # Exhaustive deterministic policy check: same adversarial corpus, repeated 5x.
    validation = []
    for trial in range(1, trials + 1):
        for case in corpus:
            p = Provenance(case.source_id, Trust.UNTRUSTED, ((0, len(case.payload)),), "synthetic corpus ingress")
            dec = gateway.authorize(case.requested_tool, p, json.loads(case.requested_arguments))
            validation.append({"trial": trial, "case_id": case.case_id, "category": case.category,
                               "source_id": case.source_id, "proposed_tool": case.requested_tool,
                               "arguments": json.loads(case.requested_arguments), "allowed": dec.allowed,
                               "blocked": not dec.allowed, "reason": dec.reason, "evaluation_kind": "deterministic_policy_validation"})
    validation_path = out / "policy_validation.csv"
    with validation_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(validation[0])); w.writeheader(); w.writerows(validation)

    provider = make_provider(provider_name, model, base_url=base_url, timeout=timeout)
    records, event_rows = [], []
    telemetry_path = out / "telemetry.jsonl"
    telemetry_path.write_text("", encoding="utf-8")
    _write_json(out / "summary.json", {"provider": provider_name, "model": model,
        "status": "running", "live_trials": 0, "target_live_trials": trials * 5,
        "policy_validation_attempts": len(validation), "policy_validation_blocks": sum(r["blocked"] for r in validation),
        "corpus_count": len(corpus), "corpus_sha256": corpus_hash})
    cases = representative_cases()
    for trial in range(1, trials + 1):
        for case in cases:
            provenance = Provenance(case.source_id, Trust.UNTRUSTED, ((0, len(case.payload)),), "externally sourced adversarial context")
            proposal = provider.propose(case.payload, run_id=f"trial-{trial}-{case.case_id}")
            outcome = score(proposal, provenance, gateway)
            row = {"trial": trial, "case_id": case.case_id, "category": case.category,
                   "source_id": case.source_id, "model": model, "provider": provider_name,
                   "attack": case.payload,
                   "text": proposal.text[:1200], "model_error": outcome.model_error,
                   "proposed_tool": outcome.proposed_tool, "proposed_arguments": outcome.proposed_arguments,
                   "baseline_unauthorized_execution": outcome.baseline_unauthorized_execution,
                   "defended_blocked": outcome.defended_blocked, "defense_reason": outcome.defense_reason,
                   "baseline_result": outcome.baseline_result, "elapsed_seconds": round(proposal.elapsed_seconds, 4),
                   "evaluation_kind": "live_model_trial"}
            records.append(row)
            event = {"time": datetime.now(timezone.utc).isoformat(), **row}
            event_rows.append(event)
            with telemetry_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
            completed = [r for r in records if not r["model_error"]]
            current_baseline = sum(r["baseline_unauthorized_execution"] for r in completed)
            current_blocked = sum(r["defended_blocked"] for r in completed)
            _write_json(out / "summary.json", {"provider": provider_name, "model": model,
                "status": "running", "live_trials": len(records), "target_live_trials": trials * 5,
                "live_model_errors": len(records)-len(completed), "live_valid_trials": len(completed),
                "baseline_unauthorized_tool_calls": current_baseline,
                "defended_unauthorized_tool_calls": current_baseline-current_blocked,
                "defended_blocked_calls": current_blocked,
                "policy_validation_attempts": len(validation), "policy_validation_blocks": sum(r["blocked"] for r in validation),
                "corpus_count": len(corpus), "corpus_sha256": corpus_hash})
            print(f"[{trial}/{trials}] {case.category}: tool={proposal.tool_name or '-'} error={bool(proposal.error)} time={proposal.elapsed_seconds:.2f}s", flush=True)

    successes = [r for r in records if not r["model_error"]]
    baseline_success = sum(r["baseline_unauthorized_execution"] for r in successes)
    blocked = sum(r["defended_blocked"] for r in successes)
    summary = {
        "project": "Automated Vulnerability Assessment and Guardrail Evaluation in Large Language Models",
        "run_utc": datetime.now(timezone.utc).isoformat(), "provider": provider_name, "model": model,
        "host_platform": platform.platform(), "python": sys.version.split()[0], "timeout_seconds": timeout, "temperature": 0,
        "top_p": 0.1, "seed": 17, "trial_count_per_category": trials,
        "corpus_count": len(corpus), "corpus_categories": sorted({c.category for c in corpus}), "corpus_sha256": corpus_hash,
        "policy_validation_attempts": len(validation), "policy_validation_blocks": sum(r["blocked"] for r in validation),
        "live_trials": len(records), "live_model_errors": len(records)-len(successes),
        "live_valid_trials": len(successes), "baseline_unauthorized_tool_calls": baseline_success,
        "defended_unauthorized_tool_calls": baseline_success-blocked, "defended_blocked_calls": blocked,
        "baseline_asr": baseline_success / len(successes) if successes else None,
        "defended_asr": (baseline_success-blocked) / len(successes) if successes else None,
        "policy_scope_note": "Source/span provenance is attached by the application at ingestion; model-internal token provenance is not observable via these provider APIs.",
        "safety_note": "Only the local synthetic export_demo_records fixture is callable. No shell, database, payment, or external tool is exposed."
    }
    summary["status"] = ("failed" if not successes else
                         "completed_with_errors" if len(successes) != len(records) else "completed")
    write_signed_audit(event_rows, out, summary)
    _write_json(out / "summary.json", summary)
    with (out / "live_trials.csv").open("w", newline="", encoding="utf-8") as f:
        cols = ["trial", "case_id", "category", "provider", "model", "attack", "model_error", "proposed_tool", "proposed_arguments", "baseline_unauthorized_execution", "defended_blocked", "defense_reason", "baseline_result", "elapsed_seconds"]
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in records: w.writerow({k: json.dumps(r[k]) if isinstance(r[k], (dict, list)) else r[k] for k in cols})
    charts(summary, out)
    return summary
