"""Base class every security check implements.

Each check inspects one narrow slice of an Azure subscription and
returns a list of Finding objects. Keeping checks small and isolated
means the scanner can grow (new checks) without touching existing ones.
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class Finding:
    check_id: str
    resource_id: str
    resource_name: str
    severity: str          # "low" | "medium" | "high" | "critical"
    description: str
    remediation: str
    cis_reference: str = ""


class BaseCheck:
    # Unique short id, e.g. "nsg-open-inbound"
    check_id: str = "base-check"
    # Default severity if the check doesn't compute it dynamically
    default_severity: str = "medium"
    cis_reference: str = ""

    def __init__(self, credential, subscription_id: str):
        self.credential = credential
        self.subscription_id = subscription_id
        # Total resources this check actually examined (pass + fail),
        # not just the ones that triggered a finding. This is the
        # denominator for the CIS-style coverage score — call
        # self._scanned() once per resource as you iterate over it,
        # regardless of whether it turns out compliant or not.
        self.total_scanned = 0

    def _scanned(self, n: int = 1) -> None:
        self.total_scanned += n

    def run(self) -> List[Finding]:
        """Override in subclasses. Return a list of Finding objects."""
        raise NotImplementedError

    def _finding(self, resource_id, resource_name, description, remediation,
                 severity: str = None) -> Finding:
        return Finding(
            check_id=self.check_id,
            resource_id=resource_id,
            resource_name=resource_name,
            severity=severity or self.default_severity,
            description=description,
            remediation=remediation,
            cis_reference=self.cis_reference,
        )
