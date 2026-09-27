# Grafana as an always-on Container App (not a Job — it needs to keep
# running, unlike the scheduled scanner) with public HTTPS ingress,
# restricted to a specific set of IP ranges. Access control here is
# network-level (only listed IPs can even reach the login page) plus
# a strong local admin password — no Azure AD dependency.

resource "azurerm_container_app" "grafana" {
  name                         = "${var.project_name}-grafana"
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"

  secret {
    name  = "grafana-admin-password"
    value = var.grafana_admin_password
  }
  secret {
    name  = "pg-admin-password"
    value = var.postgres_admin_password
  }

  template {
    container {
      name   = "grafana"
      image  = var.grafana_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name        = "GF_SECURITY_ADMIN_PASSWORD"
        secret_name = "grafana-admin-password"
      }
      env {
        name  = "GF_AUTH_ANONYMOUS_ENABLED"
        value = "false"
      }
      env {
        name  = "GF_DB_HOST"
        value = azurerm_postgresql_flexible_server.this.fqdn
      }
      env {
        name  = "GF_DB_USER"
        value = var.postgres_admin_user
      }
      env {
        name        = "GF_DB_PASSWORD"
        secret_name = "pg-admin-password"
      }
      env {
        name  = "GF_DB_NAME"
        value = azurerm_postgresql_flexible_server_database.cspm.name
      }
    }
  }

  ingress {
    external_enabled = true
    target_port      = 3000
    transport         = "auto"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }

    # Once any rule is set here, unmatched traffic is denied by
    # default — so only the ranges listed in allowed_grafana_ip_ranges
    # can reach Grafana at all, before they even see the login page.
    dynamic "ip_security_restriction" {
      for_each = { for idx, cidr in var.allowed_grafana_ip_ranges : idx => cidr }
      content {
        name             = "allow-${ip_security_restriction.key}"
        action           = "Allow"
        ip_address_range = ip_security_restriction.value
        description      = "Allowed range ${ip_security_restriction.key}"
      }
    }
  }
}

output "grafana_url" {
  value = "https://${azurerm_container_app.grafana.ingress[0].fqdn}"
}
