from azure.mgmt.sql import SqlManagementClient
from .base import BaseCheck


class SQLOpenFirewallCheck(BaseCheck):
    check_id = "sql-firewall-open"
    default_severity = "critical"
    cis_reference = "CIS Azure 4.1"

    def run(self):
        findings = []
        client = SqlManagementClient(self.credential, self.subscription_id)

        for server in client.servers.list():
            self._scanned()  # one SQL server = one resource

            resource_group = server.id.split("/")[4]
            rules = client.firewall_rules.list_by_server(resource_group, server.name)

            for rule in rules:
                if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address in (
                    "255.255.255.255", "0.0.0.0"
                ):
                    findings.append(self._finding(
                        resource_id=server.id,
                        resource_name=server.name,
                        description=(
                            f"Firewall rule '{rule.name}' allows access from "
                            "any IP address."
                        ),
                        remediation=(
                            "Restrict the rule to known IP ranges, or use "
                            "VNet service endpoints / Private Link instead."
                        ),
                    ))
        return findings
