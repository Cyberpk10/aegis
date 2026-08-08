from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

from app.db.models import AuditReport, Case


def _make_case(db_session, *, verdict, created_at, framework_mappings=None):
    case = Case(
        id=uuid.uuid4(),
        created_at=created_at,
        filename="test.eml",
        verdict=verdict,
        score=50,
        from_addr="sender@example.com",
        subject="Test",
        indicators=[],
        framework_mappings=framework_mappings or {},
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


MITRE_T1598 = {"mitre_attack": [{"indicator_id": "URGENCY_LANGUAGE", "control_id": "T1598"}]}
MITRE_T1656 = {"mitre_attack": [{"indicator_id": "AUTH_SPF_FAIL", "control_id": "T1656"}]}


def test_get_audit_evidence_reflects_seeded_cases(client, db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), framework_mappings=MITRE_T1598)
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 10), framework_mappings=MITRE_T1598)
    _make_case(db_session, verdict="suspicious", created_at=datetime(2026, 1, 12), framework_mappings=MITRE_T1656)
    # Outside the period — must not be counted.
    _make_case(db_session, verdict="malicious", created_at=datetime(2025, 6, 1), framework_mappings=MITRE_T1598)

    response = client.get(
        "/api/audit/evidence",
        params={"framework": "mitre", "date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["framework_key"] == "mitre_attack"
    assert body["total_controls"] == 7
    assert body["operating_controls"] == 2

    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["T1598"]["detection_count"] == 2
    assert by_id["T1598"]["operating"] is True
    assert by_id["T1656"]["detection_count"] == 1
    assert by_id["T1566.002"]["detection_count"] == 0
    assert by_id["T1566.002"]["operating"] is False


def test_get_audit_evidence_unknown_framework_returns_422(client):
    response = client.get("/api/audit/evidence", params={"framework": "not-a-real-framework"})
    assert response.status_code == 422


def test_get_audit_evidence_accepts_all_four_framework_aliases(client):
    expected_keys = {
        "nist": "nist_csf",
        "iso": "iso_27001",
        "soc2": "soc2",
        "mitre": "mitre_attack",
    }
    for alias, expected_key in expected_keys.items():
        response = client.get("/api/audit/evidence", params={"framework": alias})
        assert response.status_code == 200
        assert response.json()["framework_key"] == expected_key


def test_generate_audit_report_persists_row_and_files_matching_evidence(client, db_session):
    case_a = _make_case(
        db_session, verdict="malicious", created_at=datetime(2026, 1, 5), framework_mappings=MITRE_T1598
    )
    _make_case(db_session, verdict="suspicious", created_at=datetime(2026, 1, 12), framework_mappings=MITRE_T1656)

    response = client.post(
        "/api/audit/report",
        json={
            "framework": "mitre",
            "date_from": "2026-01-01T00:00:00",
            "date_to": "2026-01-31T23:59:59",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["framework_key"] == "mitre_attack"
    assert body["total_controls"] == 7
    assert body["operating_controls"] == 2
    assert body["total_supporting_cases"] == 2

    report_id = uuid.UUID(body["id"])
    row = db_session.get(AuditReport, report_id)
    assert row is not None
    assert row.framework_key == "mitre_attack"
    assert row.total_controls == 7
    assert row.operating_controls == 2

    pdf_path = Path(row.pdf_path)
    json_path = Path(row.json_path)
    assert pdf_path.exists()
    assert json_path.exists()
    assert pdf_path.read_bytes()[:4] == b"%PDF"

    payload = json.loads(json_path.read_text())["aegis_audit_evidence_pack"]
    assert payload["framework_key"] == "mitre_attack"
    assert payload["integrity"]["total_controls"] == 7
    assert payload["integrity"]["operating_controls"] == 2
    assert payload["integrity"]["total_supporting_cases"] == 2

    controls_by_id = {c["control_id"]: c for c in payload["controls"]}
    assert controls_by_id["T1598"]["detection_count"] == 1
    assert controls_by_id["T1598"]["sample_cases"][0]["id"] == str(case_a.id)
    assert controls_by_id["T1656"]["detection_count"] == 1
    assert controls_by_id["T1566.002"]["detection_count"] == 0
    assert controls_by_id["T1566.002"]["operating"] is False


def test_generate_audit_report_for_unknown_framework_alias_returns_422(client):
    response = client.post(
        "/api/audit/report",
        json={"framework": "not-a-real-framework"},
    )
    assert response.status_code == 422


def test_list_audit_reports_includes_generated_report(client, db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), framework_mappings=MITRE_T1598)

    create_response = client.post(
        "/api/audit/report",
        json={"framework": "mitre", "date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )
    report_id = create_response.json()["id"]

    list_response = client.get("/api/audit/reports")

    assert list_response.status_code == 200
    body = list_response.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == report_id
    assert body["items"][0]["framework_name"] == "MITRE ATT&CK"


def test_download_audit_report_returns_stored_bytes_for_both_formats(client, db_session):
    _make_case(db_session, verdict="malicious", created_at=datetime(2026, 1, 5), framework_mappings=MITRE_T1598)

    create_response = client.post(
        "/api/audit/report",
        json={"framework": "mitre", "date_from": "2026-01-01T00:00:00", "date_to": "2026-01-31T23:59:59"},
    )
    report_id = create_response.json()["id"]
    row = db_session.get(AuditReport, uuid.UUID(report_id))

    pdf_response = client.get(f"/api/audit/reports/{report_id}/download", params={"format": "pdf"})
    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"] == "application/pdf"
    assert pdf_response.content == Path(row.pdf_path).read_bytes()

    json_response = client.get(f"/api/audit/reports/{report_id}/download", params={"format": "json"})
    assert json_response.status_code == 200
    assert json_response.headers["content-type"] == "application/json"
    assert json_response.content == Path(row.json_path).read_bytes()


def test_download_nonexistent_report_returns_404(client):
    response = client.get(
        f"/api/audit/reports/{uuid.uuid4()}/download", params={"format": "pdf"}
    )
    assert response.status_code == 404
