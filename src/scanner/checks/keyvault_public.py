from azure.mgmt.keyvault import KeyVaultManagementClient
from .base import BaseCheck


class KeyVaultPublicAccessCheck(BaseCheck):
    check_id = "keyvault-public-access"
    default_severity = "high"
    cis_reference = "CIS Azure 8.4 / 8.5"

    def run(self):
        findings = []
        client = KeyVaultManagementClient(self.credential, self.subscription_id)

        for vault in client.vaults.list():
            self._scanned()  # one Key Vault = one resource

            props = vault.properties
            acls = getattr(props, "network_acls", None)
            default_action = getattr(acls, "default_action", None) if acls else None

            if default_action != "Deny":
                findings.append(self._finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    description="Key Vault network ACLs do not default to Deny (publicly reachable).",
                    remediation="Set the network ACL default action to Deny and allow only trusted networks or Private Link.",
                ))

            if not getattr(props, "enable_purge_protection", False):
                findings.append(self._finding(
                    resource_id=vault.id,
                    resource_name=vault.name,
                    description="Key Vault does not have purge protection enabled.",
                    remediation="Enable purge protection so secrets/keys can't be permanently deleted early.",
                    severity="medium",
                ))
        return findings
