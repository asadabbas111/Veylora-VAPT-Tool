"""Unit tests for the scope enforcement service (server-side security boundary)."""
import pytest

from app.models.assessment import AssessmentScope
from app.services.scope_service import (
    ScopeValidationError,
    classify_target,
    normalize_host,
    point_in_scope,
    validate_target_against_scopes,
)


def _scope(target, target_type=None):
    return AssessmentScope(
        assessment_id=1, target=target,
        target_type=target_type or classify_target(target),
        description="test", created_by=1,
    )


def test_classify_target_types():
    assert classify_target("192.168.56.0/24") == "cidr"
    assert classify_target("192.168.56.101") == "ipv4"
    assert classify_target("scanme.example.com") == "hostname"
    assert classify_target("http://lab.internal/panel") == "url"
    assert classify_target("fd00::1") == "ipv6"


def test_classify_target_rejects_garbage():
    with pytest.raises(ScopeValidationError):
        classify_target("not a valid target!!")


def test_normalize_host():
    assert normalize_host("HTTP://Lab.INTERNAL:8080/path") == "lab.internal"
    assert normalize_host("scanme.example.com") == "scanme.example.com"


def test_point_in_scope_ip_in_cidr():
    ok, _ = point_in_scope("192.168.56.10", "192.168.56.0/24")
    assert ok is True
    ok, _ = point_in_scope("192.168.57.10", "192.168.56.0/24")
    assert ok is False


def test_point_in_scope_hostname_matches():
    ok, reason = point_in_scope("scanme.example.com", "*.example.com")
    assert ok is True
    ok, _ = point_in_scope("unrelated.org", "*.example.com")
    assert ok is False
    assert reason  # human-readable explanation present


def test_domain_scope_authorizes_subdomains():
    ok, _ = point_in_scope("sub.example.com", "example.com", "domain")
    assert ok is True
    ok, _ = point_in_scope("example.org", "example.com", "domain")
    assert ok is False


def test_hostname_scope_is_exact_only():
    # A hostname scope must NOT authorize a sibling subdomain.
    ok, _ = point_in_scope("x.scanme.example.com", "scanme.example.com", "hostname")
    assert ok is False


def test_domain_scope_validated_via_scopes():
    result = validate_target_against_scopes("sub.example.com", [_scope("*.example.com")])
    assert result.in_scope is True
    result = validate_target_against_scopes("evil.org", [_scope("*.example.com")])
    assert result.in_scope is False


def test_validate_target_blocks_out_of_scope():
    result = validate_target_against_scopes("8.8.8.8", [_scope("192.168.56.0/24")])
    assert result.in_scope is False


def test_validate_target_allows_in_scope():
    result = validate_target_against_scopes("192.168.56.77", [_scope("192.168.56.0/24")])
    assert result.in_scope is True
    assert result.matched_scope == "192.168.56.0/24"


def test_validate_target_no_scopes_denies_everything():
    result = validate_target_against_scopes("192.168.56.1", [])
    assert result.in_scope is False


def test_validate_target_rejects_private_target_without_scope():
    result = validate_target_against_scopes("10.0.0.5", [_scope("scanme.example.com")])
    assert result.in_scope is False