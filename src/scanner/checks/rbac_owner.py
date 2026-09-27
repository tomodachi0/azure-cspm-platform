from azure.mgmt.authorization import AuthorizationManagementClient
from .base import BaseCheck

OWNER_ROLE_NAME = "Owner"


class SubscriptionOwnerCheck(BaseCheck):
    """Flags individual users (not groups/service principals) holding
    Owner directly at subscription scope. The control applies to every
    role assignment at subscription scope, so total_scanned counts all
    of them, not just the Owner ones — that's the denominator for the
    coverage score.

    Note: principal_type on role assignments depends on the API version
    the SDK negotiates. If it comes back None for your tenant, resolving
    the actual type requires a Microsoft Graph lookup by principal_id —
    a good future extension, not required for the check to run.
    """
    check_id = "rbac-owner-at-subscription"
    default_severity = "high"
    cis_reference = "CIS Azure 1.23"

    def run(self):
        findings = []
        client = AuthorizationManagementClient(self.credential, self.subscription_id)
        scope = f"/subscriptions/{self.subscription_id}"

        role_names = {
            rd.id: rd.role_name for rd in client.role_definitions.list(scope)
        }

        for assignment in client.role_assignments.list_for_scope(scope):
            self._scanned()  # one role assignment = one resource under this control

            role_name = role_names.get(assignment.role_definition_id, "")
            if role_name != OWNER_ROLE_NAME:
                continue
            if getattr(assignment, "principal_type", None) not in (None, "User"):
                continue  # groups/service principals handled separately

            findings.append(self._finding(
                resource_id=assignment.id,
                resource_name=assignment.principal_id,
                description="Individual principal assigned Owner directly at subscription scope.",
                remediation="Assign Owner to a group with PIM/just-in-time activation instead of directly to a user.",
            ))
        return findings
