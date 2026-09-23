from azure.mgmt.compute import ComputeManagementClient
from .base import BaseCheck


class UnencryptedDiskCheck(BaseCheck):
    check_id = "disk-encryption"
    default_severity = "high"
    cis_reference = "CIS Azure 7.2"

    def run(self):
        findings = []
        client = ComputeManagementClient(self.credential, self.subscription_id)

        for disk in client.disks.list():
            enc = getattr(disk, "encryption", None)
            enc_type = getattr(enc, "type", None) if enc else None

            if enc_type in (None, "EncryptionAtRestWithPlatformKey"):
                # Platform-managed key is the *minimum*; flag as low so it
                # doesn't drown out disks with no encryption at all.
                if enc_type is None:
                    findings.append(self._finding(
                        resource_id=disk.id,
                        resource_name=disk.name,
                        description="Managed disk has no encryption configuration set.",
                        remediation="Enable encryption at rest, ideally with a customer-managed key (CMK).",
                        severity="critical",
                    ))
                else:
                    findings.append(self._finding(
                        resource_id=disk.id,
                        resource_name=disk.name,
                        description="Disk uses platform-managed key, not customer-managed key.",
                        remediation="Consider a customer-managed key (Key Vault) for sensitive workloads.",
                        severity="low",
                    ))
        return findings
