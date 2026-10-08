"""Adapter contract every hypervisor plugin must implement."""
from abc import ABC, abstractmethod


class BaseAdapter(ABC):
    """
    One instance per hypervisor_instance row. The collector calls these
    methods in order and receives plain dicts back — the adapter is
    responsible for all platform-specific API handling (SOAP, REST, etc).
    """

    #: short platform key matching hypervisor_types.type_key
    type_key: str = ""

    def __init__(self, instance):
        """
        instance: dict with keys {id, name, host, port, credential_ref,
                                  connection_options, hypervisor_type_id}
        """
        self.instance = instance
        self.instance_id = instance["id"]

    @abstractmethod
    def connect(self):
        """Establish a session. Raise on failure."""

    @abstractmethod
    def disconnect(self):
        """Clean up any session/connection."""

    @abstractmethod
    def collect_clusters(self):
        """Return a list of cluster dicts (schema: see clusters table)."""

    @abstractmethod
    def collect_hosts(self):
        """Return a list of host dicts."""

    @abstractmethod
    def collect_datastores(self):
        """Return a list of datastore dicts."""

    @abstractmethod
    def collect_vms(self):
        """Return a list of VM dicts."""

    def collect_datacenters(self):
        """Optional. Return a list of datacenter dicts. Default: []."""
        return []

    def collect_vm_disks(self, vm):
        """Optional. Return a list of disk dicts for a single VM dict."""
        return []

    def collect_vm_nics(self, vm):
        """Optional. Return a list of NIC dicts for a single VM."""
        return []

    def collect_vm_disk_usage(self, vm):
        """Optional. Return a list of partition usage dicts for a VM."""
        return []

    @classmethod
    def capabilities(cls):
        """
        Return a dict describing what this platform supports, stored in
        hypervisor_types.capabilities and read by the frontend to know
        which pages/columns to render.
        """
        return {
            "clusters": True,
            "hosts": True,
            "datastores": True,
            "vms": True,
            "datacenters": False,
            "vm_disks": False,
            "vm_nics": False,
            "vm_disk_usage": False,
        }
