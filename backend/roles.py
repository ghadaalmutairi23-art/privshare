"""The five roles and their permissions (least privilege). Enforcement lives in rbac.py."""

ROLES = ("uni_owner", "partner_rep", "analyst", "admin", "auditor")

PERMISSIONS = {
    # The only role that may see individual student records
    "uni_owner": {"approve_query_type_uni", "view_query_types", "manage_student_data",
                  "view_student_records", "manage_analyst_permissions"},
    "partner_rep": {"approve_query_type_partner", "view_query_types"},
    "analyst": {"run_query", "view_budget", "view_query_types", "view_own_permissions"},
    "admin": {"manage_users", "view_alerts"},          # no raw-data or audit-edit permission
    "auditor": {"view_audit", "verify_audit", "view_query_types"},
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())
