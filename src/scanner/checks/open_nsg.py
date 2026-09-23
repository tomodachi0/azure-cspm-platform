from azure.mgmt.network import NetworkManagementClient
from .base import BaseCheck, Finding

# Ports that should never be open to the whole internet
SENSITIVE_PORTS = {"22", "3389", "1433", "3306", "5432", "6379", "27017"}
ANY_SOURCE = {"*", "0.0.0.0/0", "Internet"}


class OpenNSGCheck(BaseCheck):
    check_id = "nsg-open-inbound"
    default_severity = "critical"
    cis_reference = "CIS Azure 6.1 / 6.2"

    def run(self):
        findings = []
        client = NetworkManagementClient(self.credential, self.subscription_id)

        for nsg in client.network_security_groups.list_all():
            rules = (nsg.security_rules or []) + (nsg.default_security_rules or [])
            for rule in rules:
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue

                sources = self._as_list(rule.source_address_prefix,
                                         rule.source_address_prefixes)
                ports = self._as_list(rule.destination_port_range,
                                       rule.destination_port_ranges)

                if not any(s in ANY_SOURCE for s in sources):
                    continue

                hit_ports = [p for p in ports if p == "*" or p in SENSITIVE_PORTS]
                if not hit_ports:
                    continue

                findings.append(self._finding(
                    resource_id=nsg.id,
                    resource_name=nsg.name,
                    description=(
                        f"Rule '{rule.name}' allows inbound access from "
                        f"any source on port(s) {', '.join(hit_ports)}"
                    ),
                    remediation=(
                        "Restrict the source address prefix to known IP "
                        "ranges (VPN/bastion) or remove the rule if unused."
                    ),
                ))
        return findings

    @staticmethod
    def _as_list(single, multiple):
        if multiple:
            return list(multiple)
        return [single] if single else []
