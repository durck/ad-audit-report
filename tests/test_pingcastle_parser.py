from pathlib import Path

from adreport.parsers import parse_pingcastle

FIXTURE = Path(__file__).parent / "fixtures" / "mini_pingcastle.xml"


def test_parse_basic_metadata():
    report = parse_pingcastle(FIXTURE)
    assert report.domain == "test.local"
    assert report.global_score == 45
    assert report.stale_objects_score == 30
    assert report.privileged_group_score == 20
    assert report.anomaly_score == 10


def test_parse_rules():
    report = parse_pingcastle(FIXTURE)
    rule_ids = {r.risk_id for r in report.rules}
    assert rule_ids == {"P-ProtectedUsers", "S-OS-2012"}
    by_id = {r.risk_id: r for r in report.rules}
    assert by_id["P-ProtectedUsers"].category == "PrivilegedAccounts"
    assert by_id["P-ProtectedUsers"].points == 10
    assert "Protected Users" in by_id["P-ProtectedUsers"].rationale
    assert by_id["S-OS-2012"].category == "StaleObjects"


def test_top_level_metrics_captured():
    report = parse_pingcastle(FIXTURE)
    assert report.metrics.get("KrbtgtLastChangeDate") == "2024-01-01T00:00:00"
    assert report.metrics.get("GuestEnabled") == "true"
    assert report.metrics.get("NumberOfDC") == "2"
