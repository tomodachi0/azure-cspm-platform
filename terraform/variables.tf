variable "location" {
  description = "Azure region"
  type        = string
  default     = "francecentral"
}

variable "project_name" {
  description = "Short name used to prefix all resources"
  type        = string
  default     = "cspm"
}

variable "subscription_id_to_scan" {
  description = "Subscription the scanner will read (Reader role only)"
  type        = string
}

variable "container_image" {
  description = "Scanner image, e.g. ghcr.io/tomodachi0/azure-cspm-platform:latest"
  type        = string
}

variable "grafana_image" {
  description = "Custom Grafana image with dashboards baked in, e.g. ghcr.io/you/azure-cspm-platform-grafana:latest"
  type        = string
}

variable "grafana_admin_password" {
  description = "Local Grafana admin password — the only login method now that AAD gating is dropped, so make it strong."
  type        = string
  sensitive   = true
}

variable "allowed_grafana_ip_ranges" {
  description = "CIDR ranges allowed to reach Grafana at all (e.g. your home IP as \"x.x.x.x/32\", a school network range). Anything not listed is denied at the network level, before it ever reaches the login page. Find your own IP with: curl ifconfig.me"
  type        = list(string)
}

variable "postgres_admin_user" {
  type    = string
  default = "cspmadmin"
}

variable "postgres_admin_password" {
  type      = string
  sensitive = true
}


