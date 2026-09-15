output "project" {
  value = var.project
}

output "hub" {
  value = {
    name        = google_compute_instance.hub.name
    zone        = google_compute_instance.hub.zone
    public_ip   = local.hub_ip
    internal_ip = google_compute_instance.hub.network_interface[0].network_ip
  }
}

output "fleet_hosts" {
  value = {
    for k, vm in google_compute_instance.fleet : k => {
      name        = vm.name
      zone        = vm.zone
      public_ip   = local.fleet_ip[k]
      internal_ip = vm.network_interface[0].network_ip
      country     = var.fleet_hosts[k].country
    }
  }
}

# The deploy/.env values that follow from the infrastructure. deploy.sh writes
# them in; everything else in .env is yours.
output "env" {
  value = {
    # SSH over the private address, advertise the static public one.
    STONECHAT_FLEET_HOSTS = join(",", [
      for k, vm in google_compute_instance.fleet :
      "${k}=ssh://${local.fleet_user}@${vm.network_interface[0].network_ip}|${local.fleet_ip[k]}|${var.fleet_hosts[k].country}"
    ])
    # Only used when the push_gateway compose profile is on.
    STONECHAT_PUSH_BIND    = google_compute_instance.hub.network_interface[0].network_ip
    STONECHAT_PUSH_GATEWAY = "http://${google_compute_instance.hub.network_interface[0].network_ip}:8100"
  }
}
