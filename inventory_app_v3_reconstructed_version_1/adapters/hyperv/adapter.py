"""
Hyper-V adapter. Talks to a Hyper-V host over WinRM using pywinrm +
PowerShell (Get-VM, Get-VMHost, Get-ClusterNode, Get-ClusterSharedVolume).
"""
import json
import logging

import winrm

from adapters.base import BaseAdapter

logger = logging.getLogger("inventory_app.adapters.hyperv")


PS_HOST_INFO = r"""
$vmHost = Get-VMHost
$info = [ordered]@{
  name          = $vmHost.Name
  manufacturer  = $vmHost.Manufacturer
  model         = $vmHost.Model
  cpu_model     = $vmHost.ProcessorName
  cpu_cores     = $vmHost.LogicalProcessorCount
  cpu_speed_mhz = $vmHost.ProcessorSpeed
  memory_total_mb = [int]($vmHost.MemoryCapacity / 1MB)
  memory_used_mb  = [int](($vmHost.MemoryCapacity - $vmHost.MemoryAvailable) / 1MB)
  os_version    = $vmHost.OperatingSystemVersion
  uptime_days   = [int]((Get-Date) - $vmHost.LastBootUpTime).TotalDays
}
$info | ConvertTo-Json -Compress
"""

PS_VMS = r"""
$vms = Get-VM | ForEach-Object {
  $vm = $_
  $ips = @()
  try { $ips = ($vm | Get-VMNetworkAdapter).IPAddresses | Where-Object { $_ -match '^\d' } } catch {}
  [ordered]@{
    native_id    = if ($vm.Id) { $vm.Id.Guid } else { "$($vm.Name)|$($vm.ClusterName)" }
    name         = $vm.Name
    cpu_count    = $vm.ProcessorCount
    memory_mb    = [int]($vm.MemoryStartup / 1MB)
    actual_memory_mb = [int]($vm.MemoryAssigned / 1MB)
    power_state  = "$($vm.State)"
    os           = $vm.OperatingSystem
    is_template  = if ($vm.IsTemplate) { 1 } else { 0 }
    primary_ip   = if ($ips.Count -gt 0) { $ips[0] } else { $null }
    all_ips      = ($ips -join ', ')
    host_name    = $vm.ComputerName
    cluster_name = $vm.ClusterName
    disk_count   = ($vm | Get-VMHardDiskDrive).Count
    total_disk_gb = [math]::Round((($vm | Get-VMHardDiskDrive | ForEach-Object { (Get-VHD $_.Path).Size } ) | Measure-Object -Sum).Sum / 1GB, 2)
    uptime_days  = [int]((Get-Date) - $vm.Uptime).TotalDays
  }
}
@($vms) | ConvertTo-Json -Compress
"""

PS_VOLUMES = r"""
Get-ClusterSharedVolume | ForEach-Object {
  [ordered]@{
    native_id  = $_.Name
    name       = $_.Name
    status     = "$($_.State)"
    accessible = if ($_.State -eq 'Online') { 1 } else { 0 }
    type       = 'CSVFS'
    cluster_name = $_.Cluster.Name
  }
} | ConvertTo-Json -Compress
"""


class HypervAdapter(BaseAdapter):
    type_key = "hyperv"

    def __init__(self, instance):
        super().__init__(instance)
        self.session = None

    @classmethod
    def capabilities(cls):
        return {
            "clusters": True, "hosts": True, "datastores": True, "vms": True,
            "datacenters": False, "vm_disks": True, "vm_nics": False, "vm_disk_usage": False,
        }

    def _run_ps(self, script):
        """Run a PowerShell script over WinRM, return parsed JSON."""
        r = self.session.run_ps(script)
        if r.status_code != 0:
            raise RuntimeError(f"WinRM script failed (rc={r.status_code}): {r.std_err}")
        txt = r.std_out.decode("utf-8", errors="replace").strip()
        if not txt:
            return None
        try:
            return json.loads(txt)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Bad JSON from PowerShell: {e}; raw output was {txt[:200]!r}")

    def connect(self):
        opts = self.instance.get("connection_options") or {}
        host = self.instance.get("host")
        user = opts.get("username")
        password = opts.get("password") or ""
        if not host or not user:
            raise RuntimeError(f"Hyper-V instance {self.instance_id} missing host or username")
        endpoint = f"http://{host}:5985/wsman"
        try:
            self.session = winrm.Session(endpoint, auth=(user, password), transport="ntlm")
        except Exception as e:
            raise RuntimeError(f"WinRM connect failed for {host}: {e}") from e

    def disconnect(self):
        self.session = None

    def collect_clusters(self):
        """A Hyper-V cluster has one logical 'cluster' row per ClusterName."""
        vms = self._run_ps(PS_VMS) or []
        if isinstance(vms, dict):
            vms = [vms]
        clusters = {}
        for vm in vms:
            cn = vm.get("cluster_name")
            if cn and cn not in clusters:
                clusters[cn] = {
                    "native_id": cn, "name": cn,
                    "num_hosts": None, "num_vms": 0,
                    "cpu_total_mhz": None, "cpu_used_mhz": None, "cpu_free_mhz": None,
                    "cpu_usage_percent": None,
                    "num_cpu_cores": None, "num_cpu_threads": None,
                    "memory_total_mb": None, "memory_used_mb": None, "memory_free_mb": None,
                    "memory_usage_percent": None,
                    "storage_total_gb": None, "storage_used_gb": None, "storage_free_gb": None,
                    "storage_usage_percent": None,
                    "config_status": None, "overall_status": None,
                    "ha_enabled": None, "drs_enabled": None,
                    "extra": {},
                }
            if cn:
                clusters[cn]["num_vms"] += 1
        return list(clusters.values())

    def collect_hosts(self):
        info = self._run_ps(PS_HOST_INFO) or {}
        if isinstance(info, list):
            info = info[0] if info else {}
        return [{
            "native_id": info.get("name"),
            "name": info.get("name"),
            "ip_address": self.instance.get("host"),
            "vendor": info.get("manufacturer"),
            "model": info.get("model"),
            "cpu_model": info.get("cpu_model"),
            "cpu_cores": info.get("cpu_cores"),
            "cpu_threads": info.get("cpu_cores"),
            "cpu_mhz": info.get("cpu_speed_mhz"),
            "memory_total_mb": info.get("memory_total_mb"),
            "memory_used_mb": info.get("memory_used_mb"),
            "power_state": "Running",
            "connection_state": "Connected",
            "maintenance_mode": 0,
            "os_name": "Windows Server",
            "os_version": info.get("os_version"),
            "uptime_days": info.get("uptime_days"),
            "cluster_name": None,
            "extra": {},
        }]

    def collect_datastores(self):
        vols = self._run_ps(PS_VOLUMES) or []
        if isinstance(vols, dict):
            vols = [vols]
        out = []
        for v in vols:
            out.append({
                "native_id": v["native_id"],
                "name": v["name"],
                "status": v.get("status"),
                "accessible": v.get("accessible", 1),
                "type": v.get("type", "CSVFS"),
                "num_vms": None,
                "capacity_gb": None, "used_gb": None, "free_gb": None,
                "free_percent": None, "provisioned_gb": None, "thin_savings_gb": None,
                "cluster_name": v.get("cluster_name"),
                "extra": {},
            })
        return out

    def collect_vms(self):
        vms = self._run_ps(PS_VMS) or []
        if isinstance(vms, dict):
            vms = [vms]
        out = []
        for vm in vms:
            out.append({
                "native_id": vm.get("native_id") or f"{vm['name']}|{vm.get('cluster_name','')}",
                "name": vm["name"],
                "cpu_count": vm.get("cpu_count"),
                "memory_mb": vm.get("memory_mb"),
                "actual_disk_gb": None,
                "power_state": vm.get("power_state"),
                "os_name": vm.get("os"),
                "primary_ip": vm.get("primary_ip"),
                "all_ips": vm.get("all_ips"),
                "hostname": vm.get("host_name"),
                "nic_count": None,
                "disk_count": vm.get("disk_count"),
                "total_disk_gb": vm.get("total_disk_gb"),
                "uptime_days": vm.get("uptime_days"),
                "is_template": vm.get("is_template", 0),
                "host_name": vm.get("host_name"),
                "cluster_name": vm.get("cluster_name"),
                "extra": {},
            })
        return out
