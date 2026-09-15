# Two kinds of machine, never merged: the hub (directory + provisioning
# credentials, one HTTPS port) and fleet hosts (every mailbox, a wide open
# port range). deploy/README.md "Topology rule".
#
# This file owns the infrastructure and the first-boot preparation of each box.
# Everything that needs both boxes up, or that carries secrets — authorizing
# the hub on the fleet hosts, the code, deploy/.env — is deploy.sh, so no
# secret ever lands in Terraform state.

locals {
  fleet_user = "stonechat-fleet"

  # Docker publishes each mailbox on a random host port from the kernel's
  # ephemeral range (hub/app/providers/fleet.py).
  mailbox_ports = "32768-60999"
}

# -- hub ------------------------------------------------------------------------

resource "google_compute_address" "hub" {
  count  = var.hub.existing_address == null ? 1 : 0
  name   = "${var.hub.name}-ip"
  region = var.region
}

data "google_compute_address" "hub" {
  count  = var.hub.existing_address == null ? 0 : 1
  name   = var.hub.existing_address
  region = var.region
}

locals {
  hub_ip = one(concat(google_compute_address.hub[*].address, data.google_compute_address.hub[*].address))
}

resource "google_compute_instance" "hub" {
  name                      = var.hub.name
  machine_type              = var.hub.machine_type
  zone                      = var.zone
  tags                      = ["stonechat-hub"]
  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.hub.disk_gb
      type  = "pd-standard"
    }
  }

  network_interface {
    network = var.network
    access_config {
      nat_ip = local.hub_ip
    }
  }

  # `startup-script` metadata, not metadata_startup_script: changing the latter
  # replaces the VM, and with it hub.db.
  metadata = {
    startup-script = templatefile("${path.module}/bootstrap/hub.sh.tftpl", {
      swap_gb = var.swap_gb
    })
  }

  dynamic "service_account" {
    for_each = var.hub.service_account == null ? [] : [var.hub.service_account]
    content {
      email  = service_account.value
      scopes = ["cloud-platform"]
    }
  }

  lifecycle {
    # An image family resolves to a newer image over time; that must not
    # replace a running hub.
    ignore_changes = [boot_disk[0].initialize_params[0].image]
  }
}

resource "google_compute_firewall" "hub_https" {
  name    = "stonechat-allow-hub-https"
  network = var.network

  # :80 answers the ACME challenge; 443/udp is HTTP/3.
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
  allow {
    protocol = "udp"
    ports    = ["443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["stonechat-hub"]
}

# -- fleet hosts ------------------------------------------------------------------

resource "google_compute_address" "fleet" {
  for_each = { for k, v in var.fleet_hosts : k => v if v.existing_address == null }
  name     = "stonechat-fleet-${each.key}-ip"
  region   = each.value.region
}

data "google_compute_address" "fleet" {
  for_each = { for k, v in var.fleet_hosts : k => v if v.existing_address != null }
  name     = each.value.existing_address
  region   = each.value.region
}

locals {
  # A fleet host's external IP is its advertise address, baked into every
  # mailbox address the hub hands out and never re-resolved — hence static.
  fleet_ip = merge(
    { for k, a in google_compute_address.fleet : k => a.address },
    { for k, a in data.google_compute_address.fleet : k => a.address },
  )
}

resource "google_compute_instance" "fleet" {
  for_each = var.fleet_hosts

  name                      = "stonechat-fleet-${each.key}"
  machine_type              = each.value.machine_type
  zone                      = each.value.zone
  tags                      = ["stonechat-fleet"]
  allow_stopping_for_update = true

  boot_disk {
    initialize_params {
      image = var.image
      size  = each.value.disk_gb
      type  = "pd-standard"
    }
  }

  network_interface {
    network = var.network
    access_config {
      nat_ip = local.fleet_ip[each.key]
    }
  }

  # Replacing this VM destroys every mailbox on it, so the same rule as the hub.
  metadata = {
    startup-script = templatefile("${path.module}/bootstrap/fleet.sh.tftpl", {
      swap_gb       = var.swap_gb
      fleet_host_sh = file("${path.module}/../fleet-host.sh")
    })
  }

  lifecycle {
    ignore_changes = [boot_disk[0].initialize_params[0].image]
  }
}

resource "google_compute_firewall" "fleet_mailboxes" {
  count   = length(var.fleet_hosts) > 0 ? 1 : 0
  name    = "stonechat-allow-fleet-mailboxes"
  network = var.network

  # TCP *and* UDP: the browser transport is QUIC on a port from the same range.
  # TCP alone leaves mailboxes working from phones and unreachable from browsers.
  allow {
    protocol = "tcp"
    ports    = [local.mailbox_ports]
  }
  allow {
    protocol = "udp"
    ports    = [local.mailbox_ports]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["stonechat-fleet"]
}

# The two private paths between the boxes. The default network's
# default-allow-internal already covers both; stating them keeps a custom
# network working too.

resource "google_compute_firewall" "hub_to_fleet_ssh" {
  count   = length(var.fleet_hosts) > 0 ? 1 : 0
  name    = "stonechat-allow-hub-to-fleet-ssh"
  network = var.network

  # docker -H ssh://stonechat-fleet@<internal ip>
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_tags = ["stonechat-hub"]
  target_tags = ["stonechat-fleet"]
}

resource "google_compute_firewall" "fleet_to_push_gateway" {
  count   = length(var.fleet_hosts) > 0 ? 1 : 0
  name    = "stonechat-allow-fleet-to-push-gateway"
  network = var.network

  # Mailboxes ping the push gateway on the hub's private address.
  allow {
    protocol = "tcp"
    ports    = ["8100"]
  }

  source_tags = ["stonechat-fleet"]
  target_tags = ["stonechat-hub"]
}
