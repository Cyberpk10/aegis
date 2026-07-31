from __future__ import annotations

from app.models.schemas import AuthResultValue
from app.parsing.auth_results import parse_authentication_results


def test_parses_all_pass():
    result = parse_authentication_results(
        ["mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass"]
    )
    assert result.spf == AuthResultValue.PASS
    assert result.dkim == AuthResultValue.PASS
    assert result.dmarc == AuthResultValue.PASS


def test_parses_mixed_results():
    result = parse_authentication_results(
        ["mx.example.com; spf=fail; dkim=none; dmarc=softfail"]
    )
    assert result.spf == AuthResultValue.FAIL
    assert result.dkim == AuthResultValue.NONE
    assert result.dmarc == AuthResultValue.SOFTFAIL


def test_missing_header_yields_unknown():
    result = parse_authentication_results([])
    assert result.spf == AuthResultValue.UNKNOWN
    assert result.dkim == AuthResultValue.UNKNOWN
    assert result.dmarc == AuthResultValue.UNKNOWN
    assert result.raw_header is None


def test_first_header_wins_when_multiple_present():
    result = parse_authentication_results(
        ["mx1.example.com; spf=pass", "mx2.example.com; spf=fail"]
    )
    assert result.spf == AuthResultValue.PASS
