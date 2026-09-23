from azure.mgmt.storage import StorageManagementClient
from .base import BaseCheck


class PublicStorageCheck(BaseCheck):
    check_id = "storage-public-access"
    default_severity = "high"
    cis_reference = "CIS Azure 3.7"

    def run(self):
        findings = []
        client = StorageManagementClient(self.credential, self.subscription_id)

        for account in client.storage_accounts.list():
            if account.allow_blob_public_access:
                findings.append(self._finding(
                    resource_id=account.id,
                    resource_name=account.name,
                    description=(
                        "Storage account allows public (anonymous) blob "
                        "access at the account level."
                    ),
                    remediation=(
                        "Set allowBlobPublicAccess to false and use SAS "
                        "tokens or Azure AD auth for any needed sharing."
                    ),
                ))

            if not account.enable_https_traffic_only:
                findings.append(self._finding(
                    resource_id=account.id,
                    resource_name=account.name,
                    description="Storage account does not enforce HTTPS-only traffic.",
                    remediation="Enable 'secure transfer required' on the account.",
                    severity="medium",
                ))
        return findings
