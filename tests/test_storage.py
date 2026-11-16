import pytest
from src.storage.audit_db import AuditDatabase
from src.engine.hybrid_detector import InspectionResult


@pytest.fixture
def memory_db():
    db = AuditDatabase(":memory:")
    yield db
    db.clear()


def make_dummy_result(verdict="ALLOW", risk_score=0.1, prompt="Test prompt", metadata=None):
    return InspectionResult(
        verdict=verdict,
        risk_score=risk_score,
        confidence=0.95,
        threat_level="SAFE" if verdict == "ALLOW" else "CRITICAL",
        primary_layer="LAYER_2_ML",
        injection_type="benign" if verdict == "ALLOW" else "direct",
        attack_family="benign_general" if verdict == "ALLOW" else "instruction_override",
        total_latency_ms=1.23,
        layer_latencies={"l2_ml_ms": 1.2},
        signals={"test_signal": True},
        prompt_snippet=prompt,
        metadata=metadata or {}
    )


def test_audit_database_record_and_get_history(memory_db):
    """Verify MCR-17: Single inspection record persistence and query."""
    res = make_dummy_result(verdict="ALLOW", risk_score=0.15, prompt="Safe user query", metadata={"uid": "u1"})
    row_id = memory_db.record(res)
    assert row_id == 1

    history = memory_db.get_history(limit=10)
    assert len(history) == 1
    item = history[0]
    assert item["id"] == 1
    assert item["verdict"] == "ALLOW"
    assert item["prompt_snippet"] == "Safe user query"
    assert item["risk_score"] == 0.15
    assert item["metadata"] == {"uid": "u1"}
    assert item["signals"] == {"test_signal": True}
    assert item["layer_latencies"] == {"l2_ml_ms": 1.2}


def test_audit_database_record_batch(memory_db):
    """Verify MCR-17: Batch inspection record persistence in single transaction."""
    results = [
        make_dummy_result(verdict="ALLOW", risk_score=0.1, prompt=f"Prompt {i}")
        for i in range(5)
    ]
    inserted = memory_db.record_batch(results)
    assert inserted == 5
    assert memory_db.count() == 5

    history = memory_db.get_history(limit=3)
    assert len(history) == 3


def test_audit_database_filtering_and_counts(memory_db):
    """Verify MCR-17: Filter by verdict and query counts."""
    memory_db.record(make_dummy_result(verdict="ALLOW", prompt="Query 1"))
    memory_db.record(make_dummy_result(verdict="BLOCK", prompt="Attack 1"))
    memory_db.record(make_dummy_result(verdict="ALLOW", prompt="Query 2"))

    assert memory_db.count() == 3
    assert memory_db.count(verdict="ALLOW") == 2
    assert memory_db.count(verdict="BLOCK") == 1

    allowed = memory_db.get_history(verdict="ALLOW")
    assert len(allowed) == 2
    assert all(r["verdict"] == "ALLOW" for r in allowed)

    blocked = memory_db.get_history(verdict="BLOCK")
    assert len(blocked) == 1
    assert blocked[0]["verdict"] == "BLOCK"


def test_shared_telemetry_aggregation(memory_db):
    """Verify Task 4: Atomic shared telemetry aggregation in AuditDatabase."""
    memory_db.record(make_dummy_result(verdict="ALLOW"))
    memory_db.record(make_dummy_result(verdict="BLOCK"))
    memory_db.record(make_dummy_result(verdict="AUDIT"))
    memory_db.record_batch([
        make_dummy_result(verdict="ALLOW"),
        make_dummy_result(verdict="BLOCK")
    ])

    stats = memory_db.get_telemetry_stats()
    assert stats["total_inspected"] == 5
    assert stats["total_blocked"] == 2
    assert stats["total_allowed"] == 2
    assert stats["total_audited"] == 1
    assert stats["persistent_records"] == 5
    assert stats["avg_latency_ms"] > 0


def test_multi_worker_shared_telemetry_consistency(tmp_path):
    """Verify Task 4: Multiple independent worker instances share the exact same telemetry state."""
    db_file = str(tmp_path / "shared_audit.db")

    # Worker 1 and Worker 2 instances in separate objects pointing to the same SQLite WAL file
    worker_1 = AuditDatabase(db_file)
    worker_2 = AuditDatabase(db_file)

    # Worker 1 processes 3 requests (2 ALLOW, 1 BLOCK)
    worker_1.record(make_dummy_result(verdict="ALLOW"))
    worker_1.record(make_dummy_result(verdict="ALLOW"))
    worker_1.record(make_dummy_result(verdict="BLOCK"))

    # Worker 2 processes 4 requests (1 ALLOW, 2 BLOCK, 1 AUDIT)
    worker_2.record(make_dummy_result(verdict="ALLOW"))
    worker_2.record(make_dummy_result(verdict="BLOCK"))
    worker_2.record(make_dummy_result(verdict="BLOCK"))
    worker_2.record(make_dummy_result(verdict="AUDIT"))

    # Query from Worker 1
    w1_stats = worker_1.get_telemetry_stats()
    # Query from Worker 2
    w2_stats = worker_2.get_telemetry_stats()

    # Both independent workers must see the identical, perfectly unified totals
    assert w1_stats["total_inspected"] == 7
    assert w1_stats["total_blocked"] == 3
    assert w1_stats["total_allowed"] == 3
    assert w1_stats["total_audited"] == 1
    assert w1_stats["persistent_records"] == 7

    assert w2_stats == w1_stats


def test_cleanup_by_age_ttl(memory_db):
    """Verify Task 5: Pruning logs by time-to-live threshold."""
    import time
    now = time.time()

    # Record 3 old logs (100 seconds ago)
    for i in range(3):
        memory_db.record(make_dummy_result(prompt=f"Old log {i}"), timestamp=now - 100.0)

    # Record 2 recent logs (just now)
    for i in range(2):
        memory_db.record(make_dummy_result(prompt=f"Recent log {i}"), timestamp=now)

    assert memory_db.count() == 5

    # Run cleanup with max_age_seconds = 50.0
    summary = memory_db.cleanup(max_age_seconds=50.0)
    assert summary["deleted_by_age"] == 3
    assert summary["remaining_records"] == 2
    assert memory_db.count() == 2

    # Verify only recent records remain
    remaining = memory_db.get_history()
    assert all("Recent" in r["prompt_snippet"] for r in remaining)


def test_cleanup_by_capacity_limit(memory_db):
    """Verify Task 5: Pruning logs by maximum record capacity."""
    import time
    now = time.time()

    # Insert 10 records with ascending timestamps
    for i in range(10):
        memory_db.record(make_dummy_result(prompt=f"Entry {i}"), timestamp=now + i)

    assert memory_db.count() == 10

    # Prune capacity to max 4 records
    summary = memory_db.cleanup(max_records=4)
    assert summary["deleted_by_capacity"] == 6
    assert summary["remaining_records"] == 4
    assert memory_db.count() == 4

    # Newest 4 entries (Entry 6, 7, 8, 9) must be preserved
    remaining = memory_db.get_history(limit=10)
    preserved_prompts = {r["prompt_snippet"] for r in remaining}
    assert preserved_prompts == {"Entry 6", "Entry 7", "Entry 8", "Entry 9"}


def test_cleanup_preserves_telemetry_metrics(memory_db):
    """Verify Task 5: Pruning audit log records preserves lifetime telemetry counters."""
    import time
    now = time.time()

    memory_db.record(make_dummy_result(verdict="BLOCK"), timestamp=now - 200.0)
    memory_db.record(make_dummy_result(verdict="ALLOW"), timestamp=now - 200.0)
    memory_db.record(make_dummy_result(verdict="ALLOW"), timestamp=now)

    assert memory_db.count() == 3
    pre_stats = memory_db.get_telemetry_stats()
    assert pre_stats["total_inspected"] == 3
    assert pre_stats["total_blocked"] == 1
    assert pre_stats["total_allowed"] == 2

    # Prune old records
    summary = memory_db.cleanup(max_age_seconds=100.0)
    assert summary["deleted_by_age"] == 2
    assert summary["remaining_records"] == 1

    # Telemetry lifetime counters must still reflect total 3 inspected
    post_stats = memory_db.get_telemetry_stats()
    assert post_stats["total_inspected"] == 3
    assert post_stats["total_blocked"] == 1
    assert post_stats["total_allowed"] == 2
    assert post_stats["persistent_records"] == 1


