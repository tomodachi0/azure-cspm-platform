"""Entrypoint: run every registered check against one subscription,
score the results, and write them out.

Usage:
    python -m scanner.main --subscription-id <id> [--output findings.json]

Auth: uses DefaultAzureCredential, so it works locally (az login),
in CI (federated credential), and in an Azure Function (managed identity)
without any code changes.
"""
import argparse
import dataclasses
import json
import os
import sys
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential

from scanner.checks import ALL_CHECKS
from scanner.scoring import score_findings

try:
    from scanner.storage import save_run  # optional Postgres/Prometheus sink
except ImportError:
    save_run = None


def run_scan(subscription_id: str):
    credential = DefaultAzureCredential()
    all_findings = []

    for check_cls in ALL_CHECKS:
        check = check_cls(credential, subscription_id)
        try:
            findings = check.run()
            all_findings.extend(findings)
            print(f"[ok]   {check_cls.check_id}: {len(findings)} finding(s)")
        except Exception as exc:  # noqa: BLE001 - keep scanning even if one check fails
            print(f"[fail] {check_cls.check_id}: {exc}", file=sys.stderr)

    summary = score_findings(all_findings)
    result = {
        "subscription_id": subscription_id,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": [dataclasses.asdict(f) for f in all_findings],
    }
    return result


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

    result = run_scan(args.subscription_id)

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nScore: {result['summary']['score']}/100 "
          f"(grade {result['summary']['grade']}) "
          f"— {result['summary']['total_findings']} finding(s)")
    print(f"Written to {args.output}")

    if save_run and os.environ.get("DATABASE_URL"):
        save_run(result)
    elif save_run:
        print("No DATABASE_URL set — skipping database persistence "
              "(JSON output above is unaffected).")

if __name__ == "__main__":
    main()
