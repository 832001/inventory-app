"""
Proxmox VE adapter scaffold. Implements the BaseAdapter contract but
the collection methods raise NotImplementedError — fill them in when
you're ready to onboard Proxmox. The point of this file existing is
that once the DB row for `type_key='proxmox'` is inserted with
adapter_module='adapters.proxmox.adapter' and
adapter_class='ProxmoxAdapter', the collector will pick it up with
ZERO changes to app.py, collectors/, or templates/.
"""
from adapters.base import BaseAdapter


class ProxmoxAdapter(BaseAdapter):
    type_key = "proxmox"

    @classmethod
    def capabilities(cls):
        return {
            "clusters": True, "hosts": True, "datastores": True, "vms": True,
            "datacenters": False, "vm_disks": False, "vm_nics": False, "vm_disk_usage": False,
        }

    def connect(self):     raise NotImplementedError("Proxmox adapter not yet implemented")
    def disconnect(self):  pass
    def collect_clusters(self):   return []
    def collect_hosts(self):      return []
    def collect_datastores(self): return []
    def collect_vms(self):        return []
