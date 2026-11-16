import os
import json
import time
import sqlite3
import threading
from typing import List, Dict, Any, Optional
from pathlib import Path
from contextlib import contextmanager

from src.engine.hybrid_detector import InspectionResult


class AuditDatabase:
    """
    Lightweight, persistent audit logging engine backed by SQLite with WAL mode.
    Enables low-overhead persistence for prompt inspection records and telemetry across server restarts.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.getenv("AUDIT_DB_PATH", "data/audit.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._shared_conn: Optional[sqlite3.Connection] = None

        # Ensure target directory exists if not in-memory
        if self.db_path != ":memory:":
            db_dir = Path(self.db_path).parent
            if str(db_dir) != "" and not db_dir.exists():
                db_dir.mkdir(parents=True, exist_ok=True)

        self._init_db()

    @contextmanager
    def _connection(self):
        if self.db_path == ":memory:":
            with self._lock:
                if self._shared_conn is None:
                    self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
                    self._shared_conn.row_factory = sqlite3.Row
                yield self._shared_conn
        else:
            conn = sqlite3.connect(self.db_path, timeout=15.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

    def _init_db(self):
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                prompt_snippet TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence REAL NOT NULL,
                threat_level TEXT NOT NULL,
                primary_layer TEXT NOT NULL,
                injection_type TEXT NOT NULL,
                attack_family TEXT NOT NULL,
                total_latency_ms REAL NOT NULL,
                layer_latencies TEXT,
                signals TEXT,
                metadata TEXT
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_verdict ON audit_logs (verdict);")

            # Shared telemetry table for cross-process / multi-worker consistency
            conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_summary (
                metric_name TEXT PRIMARY KEY,
                metric_value REAL NOT NULL
            );
            """)
            for key in ("total_inspected", "total_blocked", "total_allowed", "total_audited", "total_latency_ms"):
                conn.execute("INSERT OR IGNORE INTO telemetry_summary (metric_name, metric_value) VALUES (?, 0.0);", (key,))

            conn.commit()

    def record(self, result: InspectionResult, timestamp: Optional[float] = None) -> int:
        """Record a single inspection result and atomically update shared telemetry."""
        ts = time.time() if timestamp is None else timestamp
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (
                    timestamp, prompt_snippet, verdict, risk_score, confidence,
                    threat_level, primary_layer, injection_type, attack_family,
                    total_latency_ms, layer_latencies, signals, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts,
                result.prompt_snippet,
                result.verdict,
                result.risk_score,
                result.confidence,
                result.threat_level,
                result.primary_layer,
                result.injection_type,
                result.attack_family,
                result.total_latency_ms,
                json.dumps(result.layer_latencies),
                json.dumps(result.signals),
                json.dumps(result.metadata)
            ))
            row_id = cursor.lastrowid

            # Atomic shared telemetry update
            blocked = 1.0 if result.verdict == "BLOCK" else 0.0
            allowed = 1.0 if result.verdict == "ALLOW" else 0.0
            audited = 1.0 if result.verdict == "AUDIT" else 0.0

            cursor.executemany("""
                INSERT INTO telemetry_summary (metric_name, metric_value)
                VALUES (?, ?)
                ON CONFLICT(metric_name) DO UPDATE SET metric_value = metric_value + excluded.metric_value;
            """, [
                ("total_inspected", 1.0),
                ("total_blocked", blocked),
                ("total_allowed", allowed),
                ("total_audited", audited),
                ("total_latency_ms", float(result.total_latency_ms))
            ])

            conn.commit()
            return row_id

    def record_batch(self, results: List[InspectionResult], timestamp: Optional[float] = None) -> int:
        """Record a batch of inspection results and atomically update shared telemetry."""
        if not results:
            return 0
        ts = time.time() if timestamp is None else timestamp
        rows = [
            (
                ts,
                r.prompt_snippet,
                r.verdict,
                r.risk_score,
                r.confidence,
                r.threat_level,
                r.primary_layer,
                r.injection_type,
                r.attack_family,
                r.total_latency_ms,
                json.dumps(r.layer_latencies),
                json.dumps(r.signals),
                json.dumps(r.metadata)
            )
            for r in results
        ]
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO audit_logs (
                    timestamp, prompt_snippet, verdict, risk_score, confidence,
                    threat_level, primary_layer, injection_type, attack_family,
                    total_latency_ms, layer_latencies, signals, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

            # Atomic shared telemetry update
            total_count = float(len(results))
            total_blocked = float(sum(1 for r in results if r.verdict == "BLOCK"))
            total_allowed = float(sum(1 for r in results if r.verdict == "ALLOW"))
            total_audited = float(sum(1 for r in results if r.verdict == "AUDIT"))
            total_latency = float(sum(r.total_latency_ms for r in results))

            cursor.executemany("""
                INSERT INTO telemetry_summary (metric_name, metric_value)
                VALUES (?, ?)
                ON CONFLICT(metric_name) DO UPDATE SET metric_value = metric_value + excluded.metric_value;
            """, [
                ("total_inspected", total_count),
                ("total_blocked", total_blocked),
                ("total_allowed", total_allowed),
                ("total_audited", total_audited),
                ("total_latency_ms", total_latency)
            ])

            conn.commit()
            return len(rows)

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent audit inspection events ordered by timestamp descending."""
        limit = max(1, min(limit, 500))
        offset = max(0, offset)

        query = "SELECT * FROM audit_logs"
        params: List[Any] = []
        if verdict:
            query += " WHERE verdict = ?"
            params.append(verdict.upper())

        query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

            items = []
            for row in rows:
                item = dict(row)
                item["layer_latencies"] = json.loads(item["layer_latencies"]) if item["layer_latencies"] else {}
                item["signals"] = json.loads(item["signals"]) if item["signals"] else {}
                item["metadata"] = json.loads(item["metadata"]) if item["metadata"] else {}
                items.append(item)
            return items

    def count(self, verdict: Optional[str] = None) -> int:
        """Count total audit logs, optionally filtered by verdict."""
        query = "SELECT COUNT(*) FROM audit_logs"
        params: List[Any] = []
        if verdict:
            query += " WHERE verdict = ?"
            params.append(verdict.upper())

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()[0]

    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Retrieve shared telemetry metrics aggregated across all worker processes."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_name, metric_value FROM telemetry_summary;")
            rows = cursor.fetchall()
            metrics = {row[0]: row[1] for row in rows}

        total_inspected = int(metrics.get("total_inspected", 0))
        total_blocked = int(metrics.get("total_blocked", 0))
        total_allowed = int(metrics.get("total_allowed", 0))
        total_audited = int(metrics.get("total_audited", 0))
        total_latency = float(metrics.get("total_latency_ms", 0.0))

        avg_latency = round(total_latency / total_inspected, 3) if total_inspected > 0 else 0.0

        return {
            "total_inspected": total_inspected,
            "total_blocked": total_blocked,
            "total_allowed": total_allowed,
            "total_audited": total_audited,
            "persistent_records": self.count(),
            "avg_latency_ms": avg_latency
        }

    def cleanup(
        self,
        max_age_days: Optional[float] = None,
        max_age_seconds: Optional[float] = None,
        max_records: Optional[int] = None
    ) -> Dict[str, int]:
        """
        Prune audit logs based on time-to-live (max_age_days / max_age_seconds) and capacity limit (max_records).
        Preserves telemetry counters while keeping disk storage bounded.
        """
        deleted_by_age = 0
        deleted_by_capacity = 0

        # Resolve defaults from environment if not explicitly passed
        if max_age_seconds is None and max_age_days is None:
            env_age = os.getenv("AUDIT_RETENTION_DAYS")
            if env_age and env_age.strip():
                try:
                    max_age_days = float(env_age)
                except ValueError:
                    max_age_days = None

        if max_records is None:
            env_cap = os.getenv("AUDIT_MAX_RECORDS")
            if env_cap and env_cap.strip():
                try:
                    max_records = int(env_cap)
                except ValueError:
                    max_records = None

        now = time.time()
        with self._connection() as conn:
            cursor = conn.cursor()

            # 1. Prune by age (TTL)
            cutoff_ts = None
            if max_age_seconds is not None and max_age_seconds > 0:
                cutoff_ts = now - max_age_seconds
            elif max_age_days is not None and max_age_days > 0:
                cutoff_ts = now - (max_age_days * 86400.0)

            if cutoff_ts is not None:
                cursor.execute("DELETE FROM audit_logs WHERE timestamp < ?", (cutoff_ts,))
                deleted_by_age = cursor.rowcount

            # 2. Prune by capacity limit (keep most recent max_records)
            if max_records is not None and max_records > 0:
                cursor.execute("SELECT COUNT(*) FROM audit_logs")
                total_current = cursor.fetchone()[0]
                if total_current > max_records:
                    overflow = total_current - max_records
                    cursor.execute("""
                        DELETE FROM audit_logs
                        WHERE id IN (
                            SELECT id FROM audit_logs
                            ORDER BY timestamp ASC, id ASC
                            LIMIT ?
                        )
                    """, (overflow,))
                    deleted_by_capacity = cursor.rowcount

            conn.commit()

            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            remaining = cursor.fetchone()[0]

        return {
            "deleted_by_age": max(0, deleted_by_age),
            "deleted_by_capacity": max(0, deleted_by_capacity),
            "remaining_records": remaining
        }

    def clear(self):
        """Purge all logs and reset telemetry (used in testing and maintenance)."""
        with self._connection() as conn:
            conn.execute("DELETE FROM audit_logs;")
            conn.execute("UPDATE telemetry_summary SET metric_value = 0.0;")
            conn.commit()
