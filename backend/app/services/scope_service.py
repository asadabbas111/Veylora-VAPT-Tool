import ipaddress
import re
from dataclasses import dataclass

from app.models.assessment import AssessmentScope


class ScopeValidationError(ValueError):
    pass


@dataclass
class ScopeCheckResult:
    target: str
    target_type: str
    in_scope: bool
    matched_scope: str | None = None
    reason: str = ""


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def classify_target(target: str) -> str:
    t = target.strip()
    if not t:
        raise ScopeValidationError("Empty target")
    if t.startswith("*.") and _is_hostname(t[2:]):
        return "domain"  # wildcard domain scope, e.g. *.example.com
    if "/" in t:
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr"
        except ValueError:
            pass
    if "-" in t and not t.replace("-", "").replace(".", "").isdigit():
        # hostname / url detection before ip range heuristic
        if _is_hostname(t):
            return "hostname"
    if "/" in t:  # URL
        return "url"
    if t.count(":") >= 2:
        try:
            ipaddress.IPv6Address(t.split("/")[0])
            return "ipv6"
        except ValueError:
            pass
    try:
        ipaddress.IPv4Address(t)
        return "ipv4"
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(t)
        return "ipv6"
    except ValueError:
        pass
    if _is_hostname(t):
        return "hostname"
    # bare single host without protocol or dotted form
    if re.match(r"^[a-zA-Z0-9\-]+$", t):
        return "hostname"
    raise ScopeValidationError(f"Unrecognized target format: {target}")


def _is_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))


def normalize_host(value: str) -> str:
    """Strip scheme/path from URLs and lowercase hostnames."""
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/")[0].split(":")[0]
    return v


def _target_in_network(target_ip, network) -> bool:
    try:
        return ipaddress.ip_address(target_ip) in network
    except ValueError:
        return False


def _coerce_ip(value: str):
    return ipaddress.ip_address(value)


def point_in_scope(target: str, scope: str, scope_type: str | None = None) -> tuple[bool, str]:
    """Return (in_scope, matched_scope_note) for a single point target.

    scope_type is normally the stored, authoritative classification of the scope
    (the caller must not trust a re-classification that would lose intent, e.g.
    "example.com" registered as a domain would otherwise be treated as a single
    host). When omitted the scope string is classified on the fly.
    """
    target_type = classify_target(target)
    scope_type = scope_type or classify_target(scope)

    if scope_type == "cidr":
        network = ipaddress.ip_network(scope, strict=False)
        try:
            if target_type == "ipv4" or target_type == "ipv6":
                return _target_in_network(target, network), scope
            if target_type == "hostname":
                return False, scope
            return False, scope
        except ValueError:
            return False, scope

    if scope_type in ("ipv4", "ipv6"):
        try:
            return _coerce_ip(target) == _coerce_ip(scope), scope
        except ValueError:
            return False, scope

    if scope_type == "hostname":
        return normalize_host(target) == normalize_host(scope), scope

    if scope_type == "domain":
        t_host = normalize_host(target)
        s_host = normalize_host(scope)
        if s_host.startswith("*."):
            s_host = s_host[2:]
        return t_host == s_host or t_host.endswith("." + s_host), scope

    if scope_type == "url":
        t_host = normalize_host(target)
        s_host = normalize_host(scope)
        return t_host == s_host, scope

    return False, scope


def validate_target_against_scopes(
    target: str,
    scopes: list[AssessmentScope],
) -> ScopeCheckResult:
    """Server-side scope enforcement. Returns BLOCK decision information.

    Raises ScopeValidationError if the target cannot be parsed at all.
    """
    target_type = classify_target(target)

    # CIDR target must be fully contained in an authorized CIDR scope
    if target_type == "cidr":
        tnet = ipaddress.ip_network(target, strict=False)
        for s in scopes:
            if s.target_type == "cidr":
                try:
                    snet = ipaddress.ip_network(s.target, strict=False)
                except ValueError:
                    continue
                if tnet.subnet_of(snet):
                    return ScopeCheckResult(target, target_type, True, s.target, "CIDR fully contained in authorized scope")
        return ScopeCheckResult(target, target_type, False, None, "BLOCKED: CIDR target is not fully contained in authorized scope")

    for s in scopes:
        try:
            ok, matched = point_in_scope(target, s.target, s.target_type)
        except ScopeValidationError:
            continue
        if ok:
            return ScopeCheckResult(target, target_type, True, matched, "IN SCOPE")

    return ScopeCheckResult(
        target, target_type, False, None, "BLOCKED: Target is outside authorized assessment scope."
    )