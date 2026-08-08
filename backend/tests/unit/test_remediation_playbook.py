from __future__ import annotations

from app.remediation.playbook import generate_playbook


def test_generate_playbook_is_deterministic_for_the_same_indicator_set():
    indicator_ids = ["CREDENTIAL_REQUEST", "AUTH_SPF_FAIL", "LINK_SHORTENER", "URGENCY_LANGUAGE"]
    first = generate_playbook(indicator_ids)
    second = generate_playbook(list(indicator_ids))  # fresh list instance, same contents
    assert first == second


def test_generate_playbook_is_order_independent_in_the_input():
    a = generate_playbook(["CREDENTIAL_REQUEST", "AUTH_SPF_FAIL"])
    b = generate_playbook(["AUTH_SPF_FAIL", "CREDENTIAL_REQUEST"])
    assert a == b


def test_empty_indicator_list_produces_empty_playbook():
    assert generate_playbook([]) == []


def test_unknown_indicator_ids_produce_no_steps():
    assert generate_playbook(["SOME_FUTURE_INDICATOR"]) == []


def test_block_sender_domain_step_triggers_on_auth_failures():
    steps = generate_playbook(["AUTH_SPF_FAIL"])
    assert len(steps) == 1
    assert steps[0].step_id == "BLOCK_SENDER_DOMAIN"
    assert steps[0].related_indicator_ids == ["AUTH_SPF_FAIL"]


def test_reset_credentials_and_notify_both_trigger_on_credential_request():
    steps = generate_playbook(["CREDENTIAL_REQUEST"])
    step_ids = {s.step_id for s in steps}
    assert "RESET_CREDENTIALS" in step_ids
    assert "NOTIFY_TARGETED_USER" in step_ids


def test_verify_payment_and_notify_both_trigger_on_payment_request():
    steps = generate_playbook(["PAYMENT_REQUEST"])
    step_ids = {s.step_id for s in steps}
    assert "VERIFY_PAYMENT_OUT_OF_BAND" in step_ids
    assert "NOTIFY_TARGETED_USER" in step_ids


def test_quarantine_copies_step_triggers_on_link_and_attachment_indicators():
    steps = generate_playbook(["LINK_SHORTENER", "ATTACHMENT_MACRO_ENABLED"])
    assert len(steps) == 1
    assert steps[0].step_id == "QUARANTINE_COPIES"
    assert steps[0].related_indicator_ids == ["ATTACHMENT_MACRO_ENABLED", "LINK_SHORTENER"]


def test_step_order_is_fixed_regardless_of_which_indicators_are_present():
    steps = generate_playbook(
        ["PAYMENT_REQUEST", "CREDENTIAL_REQUEST", "AUTH_SPF_FAIL", "LINK_SHORTENER"]
    )
    step_ids = [s.step_id for s in steps]
    assert step_ids == [
        "BLOCK_SENDER_DOMAIN",
        "RESET_CREDENTIALS",
        "VERIFY_PAYMENT_OUT_OF_BAND",
        "QUARANTINE_COPIES",
        "NOTIFY_TARGETED_USER",
    ]
