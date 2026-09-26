terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "this" {
  name     = "${var.project_name}-rg"
  location = var.location
}

# Read-only identity the scanner runs as. Least privilege: Reader only,
# assigned below, nothing else.
resource "azurerm_user_assigned_identity" "scanner" {
  name                = "${var.project_name}-scanner-identity"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
}

resource "azurerm_role_assignment" "scanner_reader" {
  scope                = "/subscriptions/${var.subscription_id_to_scan}"
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.scanner.principal_id
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.project_name}-logs"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_container_app_environment" "this" {
  name                       = "${var.project_name}-env"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  # Explicit workload profile — without this, Azure creates a
  # lightweight "Express" environment that doesn't support Container
  # App Jobs (only plain Container Apps).
  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  lifecycle {
    ignore_changes = [workload_profile, log_analytics_workspace_id]
  }
}

# Plain always-on Container App instead of a Job — this subscription's
# environment is on Azure's "Express" tier (a platform-level default we
# can't opt out of from Terraform or the CLI), and Express doesn't
# support Jobs. Regular Container Apps work fine on Express, so the
# scanner loops and sleeps internally (LOOP_FOREVER=true) instead of
# relying on Azure's Job scheduler.
resource "azurerm_container_app" "scanner" {
  name                         = "${var.project_name}-scanner"
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  revision_mode                = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanner.id]
  }

  secret {
    name  = "database-url"
    value = "postgresql://${urlencode(var.postgres_admin_user)}:${urlencode(var.postgres_admin_password)}@${azurerm_postgresql_flexible_server.this.fqdn}:5432/${azurerm_postgresql_flexible_server_database.cspm.name}?sslmode=require"
  }

  template {
    min_replicas = 1
    max_replicas = 1

    container {
      name   = "scanner"
      image  = var.container_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "AZURE_SUBSCRIPTION_ID"
        value = var.subscription_id_to_scan
      }
      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "LOOP_FOREVER"
        value = "true"
      }
      env {
        name  = "SCAN_INTERVAL_SECONDS"
        value = "21600" # 6 hours
      }
    }
  }
}

output "resource_group" {
  value = azurerm_resource_group.this.name
}
