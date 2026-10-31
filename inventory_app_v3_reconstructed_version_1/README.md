# Inventory App v3

Flask dashboard + multi-platform collector, running against the normalized
schema `vcenter_inventory_v3`.

## Layout

- `app.py` — Flask API + UI routes
- `lifecycle.py` — VM decommission tracking
- `export_utils.py` — CSV/XLSX export helpers
- `adapters/` — hypervisor plugins (VMware, Hyper-V, Proxmox, Nutanix scaffolds)
- `collectors/collector_service.py` — orchestrates collections per instance
- `templates/` — Jinja templates (no changes required for the schema migration)

## Deploy

