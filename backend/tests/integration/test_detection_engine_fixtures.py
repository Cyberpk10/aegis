"""End-to-end wiring check for every M5 Stage 1 detector: JSON event fixtures loaded
through the full detection engine (app.detections.engine.run_detections), not just the
isolated evaluate() functions. This is the guardrail suite protecting analyst trust in
the flags — each detector must fire on its attack fixture and must NOT false-positive on
the corresponding benign near-miss fixture.
"""

from __future__ import annotations

from app.detections.engine import run_detections

_CASES = [
    ("brute_force_attack.json", "brute_force_benign.json", "BRUTE_FORCE_PASSWORD_SPRAY"),
    ("impossible_travel_attack.json", "impossible_travel_benign.json", "IMPOSSIBLE_TRAVEL"),
    ("off_hours_attack.json", "off_hours_benign.json", "OFF_HOURS_ACCESS"),
    ("mass_file_access_attack.json", "mass_file_access_benign.json", "MASS_FILE_ACCESS"),
    (
        "data_exfil_large_transfer_attack.json",
        "data_exfil_large_transfer_benign.json",
        "DATA_EXFIL_LARGE_TRANSFER",
    ),
    (
        "data_exfil_db_export_attack.json",
        "data_exfil_db_export_benign.json",
        "DATA_EXFIL_LARGE_DB_EXPORT",
    ),
    (
        "privilege_escalation_attack.json",
        "privilege_escalation_benign.json",
        "PRIVILEGE_ESCALATION",
    ),
]


def test_every_detector_fires_on_its_attack_fixture(build_event_window):
    for attack_fixture, _benign_fixture, finding_id in _CASES:
        window = build_event_window(attack_fixture)
        findings = run_detections(window)
        matched = [f for f in findings if f.id == finding_id]
        assert matched, f"{finding_id} did not fire on {attack_fixture}"


def test_every_detector_is_silent_on_its_benign_fixture(build_event_window):
    for _attack_fixture, benign_fixture, finding_id in _CASES:
        window = build_event_window(benign_fixture)
        findings = run_detections(window)
        matched = [f for f in findings if f.id == finding_id]
        assert not matched, f"{finding_id} false-positived on {benign_fixture}"
