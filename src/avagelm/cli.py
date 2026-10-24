"""Command-line interface."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from avagelm.core.providers import make_provider
from avagelm.core.runner import run
from avagelm.dashboard import serve
from avagelm.utils.audit import verify_audit


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local provenance-aware LLM agent security evaluation",
        epilog=("Examples: python main.py --check; python main.py --orchestrate --trials 5; "
                "python main.py --dashboard"),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--orchestrate", action="store_true", help="run policy validation and live paired model trials")
    modes.add_argument("--dashboard", action="store_true", help="start the loopback dashboard (it can launch a run)")
    modes.add_argument("--check", action="store_true", help="check provider reachability and model availability")
    modes.add_argument("--verify-audit", action="store_true", help="verify audit hashes and signature in --output")
    parser.add_argument("--trials", type=int, default=5, help="live trials per attack category (1-100; default: 5)")
    parser.add_argument("--provider", choices=["ollama", "vllm"], default="ollama")
    parser.add_argument("--model", default="llama3.2:latest")
    parser.add_argument("--base-url", help="override the provider URL (otherwise use OLLAMA_BASE_URL or VLLM_BASE_URL)")
    parser.add_argument("--timeout", type=float, default=300, help="request timeout in seconds (default: 300)")
    parser.add_argument("--output", default="artifacts", help="directory for run artifacts")
    parser.add_argument("--port", type=int, default=8765, help="dashboard port (default: 8765)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not any((args.orchestrate, args.dashboard, args.check, args.verify_audit)):
        parser.print_help()
        return 0
    if not 1 <= args.trials <= 100:
        parser.error("--trials must be between 1 and 100")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    output = Path(args.output).expanduser()

    try:
        if args.verify_audit:
            result = verify_audit(output)
            print(json.dumps(result, indent=2))
            return 0
        if args.dashboard:
            serve(output, args.port, provider=args.provider, model=args.model,
                  base_url=args.base_url, timeout=args.timeout)
            return 0

        provider = make_provider(args.provider, args.model, args.base_url, args.timeout)
        status = provider.check()
        print(json.dumps(status, indent=2))
        if not status["model_available"]:
            print(f"Model {args.model!r} is not listed by {args.provider}. Install it or choose an available model.", file=sys.stderr)
            return 2
        if args.check:
            print("Provider preflight passed.")
            return 0

        summary = run(output, args.provider, args.model, args.trials,
                      base_url=args.base_url, timeout=args.timeout)
        print(json.dumps(summary, indent=2), flush=True)
        return 2 if summary["status"] == "failed" else 1 if summary["status"] == "completed_with_errors" else 0
    except KeyboardInterrupt:
        print("Interrupted. Any completed telemetry remains in the output directory.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
