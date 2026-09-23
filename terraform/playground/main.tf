# PLAYGROUND ONLY — deliberately insecure resources to test the scanner
# against. Never apply this against anything but a disposable
# subscription/resource group, and always `terraform destroy` when done.
#
# Attribute names on azurerm_storage_account have changed across provider
# versions (e.g. allow_blob_public_access vs allow_nested_items_to_be_public).
# If `terraform apply` errors on an attribute name, check:
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
  storage_use_azuread = true
}

data "azurerm_client_config" "current" {}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_resource_group" "playground" {
  name     = "cspm-playground-rg"
  location = "spaincentral"
}

# Should trigger the storage-public-access check
resource "azurerm_storage_account" "insecure" {
  name                            = "cspmplay${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.playground.name
  location                        = azurerm_resource_group.playground.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
}

# Should trigger the nsg-open-inbound check (SSH open to the internet)
resource "azurerm_network_security_group" "insecure" {
  name                = "cspm-playground-nsg"
  location            = azurerm_resource_group.playground.location
  resource_group_name = azurerm_resource_group.playground.name

  security_rule {
    name                       = "AllowSSHFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Should trigger the disk-encryption check (no encryption block set)
resource "azurerm_managed_disk" "insecure" {
  name                 = "cspm-playground-disk"
  location             = azurerm_resource_group.playground.location
  resource_group_name  = azurerm_resource_group.playground.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 4
}

resource "azurerm_role_assignment" "self_blob_data" {
  scope                = azurerm_storage_account.insecure.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

output "resource_group" {
  value = azurerm_resource_group.playground.name
}

output "storage_account_name" {
  value = azurerm_storage_account.insecure.name
}
