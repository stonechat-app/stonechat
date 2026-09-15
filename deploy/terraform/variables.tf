variable "project" {
  description = "GCP project id. The Compute Engine API must be enabled."
  type        = string
}

variable "region" {
  description = "Region of the hub (and of its static IP)."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone of the hub VM. us-central1, us-west1 and us-east1 e2-micros are free tier."
  type        = string
  default     = "us-central1-a"
}

variable "network" {
  description = "VPC network both machines join."
  type        = string
  default     = "default"
}

variable "image" {
  description = "Boot image for every VM. Debian or Ubuntu: the bootstrap scripts use apt."
  type        = string
  default     = "debian-cloud/debian-12"
}

variable "swap_gb" {
  description = "Swap file size on every VM. An e2-micro has 1 GB of RAM, which is not enough to build the hub image; 0 disables."
  type        = number
  default     = 2
}

variable "hub" {
  description = <<-EOT
    The hub VM. existing_address adopts a static IP you already reserved (by
    name, in var.region) instead of creating one — it is then only read, never
    managed, so `tofu destroy` cannot release the address your DNS points at.
    service_account is only needed for the per-user-VM gcp provider.
  EOT
  type = object({
    name             = optional(string, "stonechat-hub")
    machine_type     = optional(string, "e2-micro")
    disk_gb          = optional(number, 20)
    existing_address = optional(string)
    service_account  = optional(string)
  })
  default = {}
}

variable "fleet_hosts" {
  description = <<-EOT
    Fleet hosts, keyed by the short name that becomes their entry in
    STONECHAT_FLEET_HOSTS. country is the ISO 3166-1 alpha-2 code the host
    sells: a country is offered on the Mailbox plan exactly when a host here
    declares it. existing_address works as for the hub.
  EOT
  type = map(object({
    region           = string
    zone             = string
    country          = string
    machine_type     = optional(string, "e2-micro")
    disk_gb          = optional(number, 20)
    existing_address = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for k, v in var.fleet_hosts : can(regex("^[a-z0-9]+$", k))])
    error_message = "Fleet host keys must be lowercase letters and digits (they become VM names and STONECHAT_FLEET_HOSTS entries)."
  }

  validation {
    condition     = alltrue([for v in values(var.fleet_hosts) : can(regex("^[A-Z]{2}$", v.country))])
    error_message = "country must be an uppercase ISO 3166-1 alpha-2 code, e.g. DE."
  }
}
