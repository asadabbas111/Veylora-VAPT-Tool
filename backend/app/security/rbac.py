ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}

# Permission -> allowed roles
PERMISSIONS: dict[str, set[str]] = {
    "view": {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER},
    "create_assessment": {ROLE_ADMIN, ROLE_ANALYST},
    "edit_assessment": {ROLE_ADMIN, ROLE_ANALYST},
    "run_scan": {ROLE_ADMIN, ROLE_ANALYST},
    "manage_assets": {ROLE_ADMIN, ROLE_ANALYST},
    "manage_findings": {ROLE_ADMIN, ROLE_ANALYST},
    "validate": {ROLE_ADMIN, ROLE_ANALYST},
    "approve_validation": {ROLE_ADMIN},  # active/high-level validation needs admin
    "run_ai": {ROLE_ADMIN, ROLE_ANALYST},
    "manage_remediation": {ROLE_ADMIN, ROLE_ANALYST},
    "generate_report": {ROLE_ADMIN, ROLE_ANALYST},
    "delete_report": {ROLE_ADMIN, ROLE_ANALYST},
    "delete_assessment": {ROLE_ADMIN, ROLE_ANALYST},
    "manage_users": {ROLE_ADMIN},
    "kill_switch": {ROLE_ADMIN},
    "view_audit": {ROLE_ADMIN, ROLE_ANALYST},
}


def role_has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS and role in PERMISSIONS[permission]


def ensure_permission(role: str, permission: str) -> bool:
    return role_has_permission(role, permission)