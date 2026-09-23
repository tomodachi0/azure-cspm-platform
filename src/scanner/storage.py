"""Optional persistence layer. If psycopg2 / DATABASE_URL aren't
available, main.py simply skips this and only writes the JSON file —
so the scanner still works standalone in Phase 1.
"""
import json
import os

import psycopg2

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id SERIAL PRIMARY KEY,
    subscription_id TEXT NOT NULL,
    scanned_at TIMESTAMPTZ NOT NULL,
    score INT NOT NULL,
    grade TEXT NOT NULL,
    total_findings INT NOT NULL,
    raw_result JSONB NOT NULL
);
"""


def _connect():
    dsn = os.environ["DATABASE_URL"]
    return psycopg2.connect(dsn)


def save_run(result: dict) -> None:
    conn = _connect()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(SCHEMA)
            cur.execute(
                """
                INSERT INTO scan_runs
                    (subscription_id, scanned_at, score, grade, total_findings, raw_result)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    result["subscription_id"],
                    result["scanned_at"],
                    result["summary"]["score"],
                    result["summary"]["grade"],
                    result["summary"]["total_findings"],
                    json.dumps(result),
                ),
            )
    finally:
        conn.close()
