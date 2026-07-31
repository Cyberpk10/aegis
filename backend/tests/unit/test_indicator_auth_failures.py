from __future__ import annotations

from app.indicators import auth_failures
from app.models.schemas import AuthResults, AuthResultValue
from app.parsing.eml_parser import ParsedEmail


def test_flags_all_failing_mechanisms():
    email = ParsedEmail(
        auth_results=AuthResults(
            spf=AuthResultValue.FAIL, dkim=AuthResultValue.FAIL, dmarc=AuthResultValue.FAIL
        )
    )
    ids = {i.id for i in auth_failures.evaluate(email)}
    assert ids == {"AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL"}


def test_no_flags_when_all_pass():
    email = ParsedEmail(
        auth_results=AuthResults(
            spf=AuthResultValue.PASS, dkim=AuthResultValue.PASS, dmarc=AuthResultValue.PASS
        )
    )
    assert auth_failures.evaluate(email) == []


def test_none_result_is_not_treated_as_failure():
    email = ParsedEmail(
        auth_results=AuthResults(
            spf=AuthResultValue.NONE, dkim=AuthResultValue.NONE, dmarc=AuthResultValue.NONE
        )
    )
    assert auth_failures.evaluate(email) == []


def test_softfail_scores_lower_than_hard_fail():
    hard_fail = ParsedEmail(auth_results=AuthResults(spf=AuthResultValue.FAIL))
    soft_fail = ParsedEmail(auth_results=AuthResults(spf=AuthResultValue.SOFTFAIL))
    hard_score = auth_failures.evaluate(hard_fail)[0].score
    soft_score = auth_failures.evaluate(soft_fail)[0].score
    assert hard_score > soft_score
