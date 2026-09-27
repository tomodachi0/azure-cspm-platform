"""Entrypoint: run every registered check against one subscription,
score the results, and write them out.

Local one-shot usage (unchanged):
    python -m scanner.main --subscription-id <id> [--output findings.json]

Deployed usage: set LOOP_FOREVER=true and this runs the same scan on a
repeating interval instead of once — used instead of a Container App
Job because Jobs aren't supported on this subscription's environment
(Express tier), while a plain always-on Container App is.

Auth: uses DefaultAzureCredential, so it works locally (az login),
in CI (federated credential), and in a Container App (managed identity)
without any code changes.
"""
import argparse
import dataclasses
import json
import os
import sys
import time
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential

from scanner.checks import ALL_CHECKS
from scanner.scoring import score

try:
    from scanner.storage import save_run  # optional Postgres/Prometheus sink
except ImportError:
    save_run = None


def run_scan(subscription_id: str):
    credential = DefaultAzureCredential()
    all_findings = []
    check_totals = {}
    check_meta = {}

    for check_cls in ALL_CHECKS:
        check = check_cls(credential, subscription_id)
        check_meta[check_cls.check_id] = {
            "severity": check_cls.default_severity,
            "cis_reference": check_cls.cis_reference,
        }
        try:
            findings = check.run()
            all_findings.extend(findings)
            check_totals[check_cls.check_id] = check.total_scanned
            print(f"[ok]   {check_cls.check_id}: "
                  f"{len(findings)} finding(s) / {check.total_scanned} scanned")
        except Exception as exc:  # noqa: BLE001 - keep scanning even if one check fails
            check_totals[check_cls.check_id] = check.total_scanned
            print(f"[fail] {check_cls.check_id}: {exc}", file=sys.stderr)

    summary = score(all_findings, check_totals, check_meta)

    result = {
        "subscription_id": subscription_id,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": [dataclasses.asdict(f) for f in all_findings],
    }
    return result


def run_once(subscription_id: str, output_path: str):
    result = run_scan(subscription_id)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nScore: {result['summary']['score']}/100 "
          f"(grade {result['summary']['grade']}) "
          f"— {result['summary']['total_findings']} finding(s) across "
          f"{len(result['summary']['controls'])} applicable control(s)")
    print(f"Written to {output_path}")

    if save_run and os.environ.get("DATABASE_URL"):
        save_run(result)
    elif save_run:
        print("No DATABASE_URL set — skipping database persistence "
              "(JSON output above is unaffected).")


def run_forever(subscription_id: str, output_path: str, interval_seconds: int):
    print(f"Starting scan loop — running every {interval_seconds}s "
          f"({interval_seconds / 3600:.1f}h). Press Ctrl+C to stop locally.")
    while True:
        try:
            run_once(subscription_id, output_path)
        except Exception as exc:  # noqa: BLE001 - one bad scan shouldn't kill the loop
            print(f"[loop] scan iteration failed: {exc}", file=sys.stderr)
        print(f"[loop] sleeping {interval_seconds}s until next scan...")
        time.sleep(interval_seconds)


def main():
    parser = argparse.ArgumentParser(description="Azure CSPM scanner")
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        required=False,
    )
    parser.add_argument("--output", default="findings.json")
    args = parser.parse_args()

    if not args.subscription_id:
        sys.exit("Provide --subscription-id or set AZURE_SUBSCRIPTION_ID")

    loop_forever = os.environ.get("LOOP_FOREVER", "false").lower() == "true"

    if loop_forever:
        interval_seconds = int(os.environ.get("SCAN_INTERVAL_SECONDS", 6 * 3600))
        run_forever(args.subscription_id, args.output, interval_seconds)
    else:
        run_once(args.subscription_id, args.output)


if __name__ == "__main__":
    main()
