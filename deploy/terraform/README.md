# Stonechat on Google Cloud, with OpenTofu / Terraform

The same two-machine deployment as [`../README.md`](../README.md), as code: a
hub VM and any number of fleet hosts, their static IPs and firewall rules, and
the first-boot preparation of each box. Works with `tofu` or `terraform`.

It is split in two on purpose:

| | What | Holds secrets? |
|---|---|---|
| `tofu apply` | VMs, static IPs, firewall rules. A startup script on each VM installs swap and Docker; on the hub it creates the fleet SSH key, on fleet hosts it runs [`../fleet-host.sh`](../fleet-host.sh). | No |
| `./deploy.sh` | Authorizes the hub on every fleet host, writes the infrastructure values into your `.env`, uploads the checkout and runs `docker compose up`. Re-run it for every code or config change. | Your `.env`, relay binary and APNs key go to the hub, never into Terraform state |

## Prerequisites

- `tofu` (or `terraform`) ≥ 1.6, `gcloud`, `git`, `python3`
- A GCP project with the Compute Engine API enabled
- Credentials for both tools, as an account that can manage Compute Engine:
  ```bash
  gcloud auth login
  gcloud auth application-default login     # what the Terraform provider uses
  ```
- A domain for the hub, if phones are going to use it (they need HTTPS)
- The default network's `default-allow-ssh` rule, or your own, so `gcloud compute ssh` reaches the VMs

## 1. Create the machines

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars      # project, and one entry per fleet host
tofu init
tofu apply
tofu output                   # the hub's public IP, among other things
```

Point your domain's **A record** at the hub's `public_ip` now: Caddy proves
ownership over port 80 when the hub first starts.

Already have reserved static IPs (for example, because DNS points at one)?
Set `existing_address` on the hub or a fleet host. The address is then read,
not managed, so `tofu destroy` never releases it.

## 2. Deploy

```bash
cp ../.env.example ../.env
$EDITOR ../.env               # STONECHAT_HUB_DOMAIN, STONECHAT_HUB_URL, STONECHAT_BIND=127.0.0.1,
                              # COMPOSE_PROFILES=tls, admin token, …
./deploy.sh --env ../.env --relay /path/to/stonechat-relay
```

`deploy.sh` fills in `STONECHAT_FLEET_HOSTS` itself, from the Terraform outputs.
Leave it alone in `.env`: it is overwritten on every run.

The relay binary is the static artifact from the `Build relay` workflow (see
[`../../relay/README.md`](../../relay/README.md)). Without it, dedicated-VM
provisioning is refused.

### With push notifications

Add `push_gateway` to `COMPOSE_PROFILES` (e.g. `COMPOSE_PROFILES=tls,push_gateway`),
fill in the APNs block of `.env`, and pass the key:

```bash
./deploy.sh --env ../.env --apns-key /path/to/AuthKey_XXXXXXXXXX.p8
```

`deploy.sh` then also sets `STONECHAT_PUSH_BIND` and `STONECHAT_PUSH_GATEWAY` to
the hub's private address. Mailboxes keep the gateway address they were created
with, so turn push on **before** the first mailbox is created.

## Day two

| Task | How |
|---|---|
| New code or `.env` change | `./deploy.sh --env ../.env` |
| New relay release | `./deploy.sh --env ../.env --relay …`, then roll running mailboxes: [`../README.md`](../README.md) "Upgrading the relay" |
| Add a country | Add an entry to `fleet_hosts`, `tofu apply`, `./deploy.sh --env ../.env` |
| Logs | `gcloud compute ssh <hub> --command 'cd ~/stonechat/deploy && sudo docker compose logs -f'` |

State is local (`terraform.tfstate`, gitignored). Lose it and Terraform no longer
knows these machines exist: keep a copy, or add a `gcs` backend.

## What destroys data

- **Replacing or destroying a fleet host destroys every mailbox on it.** A
  mailbox's data lives in its container's writable layer, deliberately with no
  volume behind it.
- **Replacing or destroying the hub destroys `hub.db`**, the directory.

Changing `swap_gb` or `fleet-host.sh` updates the startup script in place, and
a newer image in the family is ignored, so neither replaces a VM. Machine type
changes stop and restart the VM, which keeps its disk. Read `tofu plan` for
`must be replaced` before applying anything else.
