# Managed Postgres so scan history persists independently of any
# laptop, container restart, or docker-compose volume.

resource "azurerm_postgresql_flexible_server" "this" {
  name                    = "${var.project_name}-pg"
  resource_group_name     = azurerm_resource_group.this.name
  location                = azurerm_resource_group.this.location
  version                 = "16"
  administrator_login     = var.postgres_admin_user
  administrator_password  = var.postgres_admin_password
  storage_mb              = 32768
  sku_name                = "B_Standard_B1ms" # cheapest burstable tier
  zone                    = "1"
}

# Special rule (0.0.0.0-0.0.0.0) = "allow access from Azure services",
# which is what lets the Container Apps below reach it without a VNet.
resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure_services" {
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.this.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_postgresql_flexible_server_database" "cspm" {
  name      = "cspm"
  server_id = azurerm_postgresql_flexible_server.this.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.this.fqdn
}
