from __future__ import annotations

from pathlib import Path

from app.core.config import settings


def _post_eml(authed_client, load_eml, filename: str) -> dict:
    raw = load_eml(filename)
    response = authed_client.post("/api/analyze", files={"file": (filename, raw, "message/rfc822")})
    assert response.status_code == 200
    return response.json()


def test_list_cases_pagination(authed_client, load_eml):
    filenames = [
        "phishing_lookalike_paypal.eml",
        "phishing_bec_wire_transfer.eml",
        "benign_newsletter.eml",
    ]
    for filename in filenames:
        _post_eml(authed_client, load_eml, filename)

    page1 = authed_client.get("/api/cases", params={"page": 1, "page_size": 2}).json()
    assert page1["total"] == 3
    assert page1["page"] == 1
    assert page1["page_size"] == 2
    assert len(page1["items"]) == 2

    page2 = authed_client.get("/api/cases", params={"page": 2, "page_size": 2}).json()
    assert len(page2["items"]) == 1

    seen_filenames = {item["filename"] for item in page1["items"] + page2["items"]}
    assert seen_filenames == set(filenames)


def test_list_cases_filter_by_verdict(authed_client, load_eml):
    _post_eml(authed_client, load_eml, "phishing_lookalike_paypal.eml")
    _post_eml(authed_client, load_eml, "benign_newsletter.eml")

    response = authed_client.get("/api/cases", params={"verdict": "malicious"})
    body = response.json()

    assert body["total"] == 1
    assert body["items"][0]["verdict"] == "malicious"


def test_list_cases_filter_by_date_range(authed_client, load_eml):
    _post_eml(authed_client, load_eml, "benign_newsletter.eml")

    in_range = authed_client.get(
        "/api/cases",
        params={"date_from": "2000-01-01T00:00:00", "date_to": "2100-01-01T00:00:00"},
    ).json()
    assert in_range["total"] == 1

    out_of_range = authed_client.get("/api/cases", params={"date_from": "2100-01-01T00:00:00"}).json()
    assert out_of_range["total"] == 0


def test_get_case_not_found(authed_client):
    response = authed_client.get("/api/cases/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_delete_case(authed_client, load_eml):
    case = _post_eml(authed_client, load_eml, "benign_newsletter.eml")
    case_id = case["id"]

    delete_response = authed_client.delete(f"/api/cases/{case_id}")
    assert delete_response.status_code == 204

    get_response = authed_client.get(f"/api/cases/{case_id}")
    assert get_response.status_code == 404

    delete_again_response = authed_client.delete(f"/api/cases/{case_id}")
    assert delete_again_response.status_code == 404


def test_delete_case_removes_raw_email_file(authed_client, load_eml):
    case = _post_eml(authed_client, load_eml, "benign_newsletter.eml")
    case_id = case["id"]
    raw_path = Path(settings.raw_email_storage_dir) / f"{case_id}.eml"
    assert raw_path.exists()

    authed_client.delete(f"/api/cases/{case_id}")

    assert not raw_path.exists()


def test_cases_are_isolated_per_account(authed_client, other_account_authed_client, load_eml):
    case = _post_eml(authed_client, load_eml, "benign_newsletter.eml")
    case_id = case["id"]

    listing = other_account_authed_client.get("/api/cases").json()
    assert all(item["id"] != case_id for item in listing["items"])

    detail = other_account_authed_client.get(f"/api/cases/{case_id}")
    assert detail.status_code == 404

    delete_response = other_account_authed_client.delete(f"/api/cases/{case_id}")
    assert delete_response.status_code == 404

    still_there = authed_client.get(f"/api/cases/{case_id}")
    assert still_there.status_code == 200
