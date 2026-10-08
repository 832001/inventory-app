"""Nutanix Prism v3 adapter scaffold — see proxmox/adapter.py for the pattern."""
from adapters.base import BaseAdapter


class NutanixAdapter(BaseAdapter):
    type_key = "nutanix"

    @classmethod
    def capabilities(cls):
        return {
            "clusters": True, "hosts": True, "datastores": True, "vms": True,
            "datacenters": False, "vm_disks": False, "vm_nics": False, "vm_disk_usage": False,
        }

    def connect(self):     raise NotImplementedError("Nutanix adapter not yet implemented")
    def disconnect(self):  pass
    def collect_clusters(self):   return []
    def collect_hosts(self):      return []
    def collect_datastores(self): return []
    def collect_vms(self):        return []
