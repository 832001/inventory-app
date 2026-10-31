"""
Proxmox VE adapter.
"""
import logging
import re
from proxmoxer import ProxmoxAPI
from adapters.base import BaseAdapter

logger = logging.getLogger("inventory_app.adapters.proxmox")

def _bytes_to_gb(v): return round((v or 0) / (1024 ** 3), 2)

def _parse_disk_entry(disk_str):
    if not disk_str: return None, 0
    storage_name = disk_str.split(":", 1)[0] if ":" in disk_str else None
    m = re.search(r"size=(\d+(?:\.\d+)?)([KMGT])?", disk_str)
    if not m: return storage_name, 0
    val, unit = float(m.group(1)), (m.group(2) or "G")
    mult = {"K": 1 / (1024 ** 2), "M": 1 / 1024, "G": 1, "T": 1024}
    return storage_name, round(val * mult.get(unit, 1), 2)

def _safe(d, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict) or k not in d: return default
        d = d[k]
    return d

class ProxmoxAdapter(BaseAdapter):
    type_key = "proxmox"

    def __init__(self, instance):
        super().__init__(instance)
        self.api = None
        self.cluster_name = None
        self.node_names = []

    @classmethod
    def capabilities(cls):
        return {"clusters": True, "hosts": True, "datastores": True, "vms": True,
                "datacenters": False, "vm_disks": True, "vm_nics": False, "vm_disk_usage": False}

    def connect(self):
        from credential_crypto import decrypt_options
        opts = decrypt_options(self.instance.get("connection_options") or {})
        #opts = self.instance.get("connection_options") or {}
        host = opts.get("ip_address") or self.instance.get("host")
        user = opts.get("username") or self.instance.get("credential_ref")
        pw = opts.get("password") or ""

        if not host or not user:
            raise RuntimeError(f"Proxmox instance {self.instance_id} missing host or username")

        self.api = ProxmoxAPI(host, user=user, password=pw, verify_ssl=False)
        cluster_status = self.api.cluster.status.get()
        self.cluster_name = next((c.get("name") for c in cluster_status if c.get("type") == "cluster"), self.instance.get("name") or host)
        self.node_names = [c["name"] for c in cluster_status if c.get("type") == "node"]

    def disconnect(self): 
        self.api = None

    def collect_clusters(self):
        nodes = self.api.nodes.get()
        total_cores = 0
        used_cpu_pct_sum = 0.0
        mem_total = 0
        mem_used = 0
        vm_count = 0
        
        for n in nodes:
            try: status = self.api.nodes(n["node"]).status.get()
            except Exception: status = {}
            total_cores += int(_safe(status, "cpuinfo", "cpus", default=0) or 0)
            used_cpu_pct_sum += float(_safe(status, "cpu", default=0) or 0)
            mem_total += int(_safe(status, "memory", "total", default=0) or 0)
            mem_used  += int(_safe(status, "memory", "used",  default=0) or 0)

        try: vm_count = len(self.api.cluster.resources.get(type="vm") or [])
        except Exception: vm_count = 0
        
        try: storages = self.api.cluster.resources.get(type="storage")
        except Exception: storages = []

        unique_storages = self._dedupe_storages(storages)
        total_storage_gb = sum(s["capacity_gb"] for s in unique_storages)
        used_storage_gb  = sum(s["used_gb"]     for s in unique_storages)
        free_storage_gb  = round(total_storage_gb - used_storage_gb, 2)
        storage_pct      = round(used_storage_gb / total_storage_gb * 100, 2) if total_storage_gb else 0

        mem_total_gb = round(mem_total / (1024 ** 3), 2)
        mem_used_gb = round(mem_used / (1024 ** 3), 2)
        mem_free_gb = round(mem_total_gb - mem_used_gb, 2)
        mem_pct = round(mem_used_gb / mem_total_gb * 100, 2) if mem_total_gb else 0
        cpu_pct = round((used_cpu_pct_sum / len(nodes) * 100), 2) if nodes else 0

        return [{
            "native_id": self.cluster_name, "name": self.cluster_name,
            "num_hosts": len(nodes), "num_vms": vm_count,
            "cpu_total_mhz": None, "cpu_used_mhz": None, "cpu_free_mhz": None, "cpu_usage_percent": cpu_pct,
            "num_cpu_cores": total_cores, "num_cpu_threads": total_cores * 2,
            "memory_total_mb": round(mem_total_gb * 1024, 2), "memory_used_mb": round(mem_used_gb * 1024, 2),
            "memory_free_mb": round(mem_free_gb * 1024, 2), "memory_usage_percent": mem_pct,
            "storage_total_gb": round(total_storage_gb, 2), "storage_used_gb": round(used_storage_gb, 2),
            "storage_free_gb": round(free_storage_gb, 2), "storage_usage_percent": storage_pct,
            "ha_enabled": None, "drs_enabled": None, "config_status": "online", "overall_status": "online",
            "extra": {"node_list": ",".join(self.node_names), "cpu_used_cores": round(total_cores * cpu_pct / 100)},
        }]

    def collect_hosts(self):
        out = []
        for n in self.api.nodes.get():
            node_name = n["node"]
            try: status = self.api.nodes(node_name).status.get()
            except Exception: status = {}
            
            cpu_cores = int(_safe(status, "cpuinfo", "cpus", default=0) or 0)
            cpu_pct = round(float(_safe(status, "cpu", default=0) or 0) * 100, 2)
            mem_total_gb = _bytes_to_gb(_safe(status, "memory", "total"))
            mem_used_gb = _bytes_to_gb(_safe(status, "memory", "used"))
            
            out.append({
                "native_id": node_name, "name": node_name, "cluster_name": self.cluster_name,
                "ip_address": None, "vendor": "Proxmox", "model": None,
                "cpu_model": _safe(status, "cpuinfo", "model", default=None),
                "cpu_cores": cpu_cores, "cpu_threads": cpu_cores, "cpu_mhz": None,
                "memory_total_mb": round(mem_total_gb * 1024, 2), "memory_used_mb": round(mem_used_gb * 1024, 2),
                "power_state": n.get("status", "unknown"), "connection_state": "Connected", "maintenance_mode": 0,
                "os_name": "Proxmox VE", "os_version": status.get("pveversion", "N/A"),
                "uptime_days": round((status.get("uptime") or 0) / 86400, 1),
                "extra": {"cpu_usage_percent": cpu_pct},
            })
        return out

    def _dedupe_storages(self, rows):
        groups = {}
        for r in rows:
            storage = r.get("storage")
            node = r.get("node")
            if not storage: continue
            is_shared = bool(r.get("shared"))
            key = storage if is_shared else f"{storage}@{node}"
            
            g = groups.setdefault(key, {
                "storage": storage, "shared": is_shared, "node": node, "nodes": [],
                "type": r.get("plugintype", "N/A"), "status": r.get("status", "N/A"),
                "maxdisk": r.get("maxdisk") or 0, "disk": r.get("disk") or 0,
            })
            g["nodes"].append(node)
            if is_shared:
                g["maxdisk"] = max(g["maxdisk"], r.get("maxdisk") or 0)
                g["disk"]    = max(g["disk"],    r.get("disk")    or 0)

        out = []
        for key, g in groups.items():
            total_gb = _bytes_to_gb(g["maxdisk"])
            used_gb = _bytes_to_gb(g["disk"])
            free_gb = round(total_gb - used_gb, 2)
            free_pct = round(free_gb / total_gb * 100, 2) if total_gb else 0
            out.append({
                "native_id": key, "name": g["storage"], "node": g["node"],
                "hosts": ",".join(sorted(set(g["nodes"]))), "type": g["type"],
                "shared": g["shared"], "status": g["status"],
                "capacity_gb": total_gb, "used_gb": used_gb, "free_gb": free_gb, "free_percent": free_pct,
            })
        return out

    def collect_datastores(self):
        rows = self.api.cluster.resources.get(type="storage")
        return [{
            "native_id": s["native_id"], "name": s["name"], "cluster_name": self.cluster_name,
            "status": s["status"], "accessible": 1 if s["status"] == "available" else 0,
            "type": s["type"], "num_vms": None,
            "capacity_gb": s["capacity_gb"], "used_gb": s["used_gb"], "free_gb": s["free_gb"], "free_percent": s["free_percent"],
            "provisioned_gb": None, "thin_savings_gb": None,
            "extra": {"primary_node": s["node"], "all_nodes": s["hosts"], "shared": 1 if s["shared"] else 0},
        } for s in self._dedupe_storages(rows)]

    def _vm_dict(self, r):
        vmid = r["vmid"]
        node = r["node"]
        kind = r.get("type", "qemu")
        try:
            cfg = self.api.nodes(node).lxc(vmid).config.get() if kind == "lxc" else self.api.nodes(node).qemu(vmid).config.get()
        except Exception: 
            cfg = {}

        total_vcpu = int(cfg.get("cores", 0) or 0) * (int(cfg.get("sockets", 1) or 0) or 1)
        ram_mb = int(cfg.get("memory", 0) or 0)

        disk_count = 0
        total_disk_gb = 0.0
        vmdks = []
        for key, val in cfg.items():
            if re.match(r"^(scsi|virtio|ide|sata)\d+$", key) and "media=cdrom" not in str(val):
                storage_name, size_gb = _parse_disk_entry(val)
                if size_gb > 0:
                    disk_count += 1
                    total_disk_gb += size_gb
                    vmdks.append({"disk_path": f"{storage_name}:{val.split(',')[0]}" if storage_name else str(val), "size_gb": size_gb})

        ips = []
        if kind == "qemu" and r.get("status") == "running":
            try:
                agent = self.api.nodes(node).qemu(vmid).agent("network-get-interfaces").get()
                for iface in agent.get("result", []):
                    for ipcfg in iface.get("ip-addresses", []):
                        addr = ipcfg.get("ip-address")
                        if (addr and ipcfg.get("ip-address-type") == "ipv4" and not addr.startswith("127.") and not addr.startswith("169.254") and addr not in ips):
                            ips.append(addr)
            except Exception: 
                pass

        return {
            "native_id": f"{self.cluster_name}-{vmid}", "name": r.get("name") or f"vm-{vmid}",
            "cpu_count": total_vcpu, "memory_mb": ram_mb, "power_state": r.get("status", "unknown"),
            "os_name": cfg.get("ostype", "N/A"), "os_version": None, "is_template": 1 if r.get("template") else 0,
            "primary_ip": ips[0] if ips else None, "all_ips": ",".join(ips) if ips else None,
            "hostname": None, "nic_count": None, "disk_count": disk_count, "total_disk_gb": round(total_disk_gb, 2),
            "actual_disk_gb": None, "tools_version": None, "uptime_days": round((r.get("uptime") or 0) / 86400, 1),
            "app_name": None, "server_owner": None, "business_owner": None,
            "host_name": node, "cluster_name": self.cluster_name, "extra": {"kind": kind, "vmid": vmid},
            "_vmdks": vmdks,
        }

    def collect_vms(self):
        return [self._vm_dict(r) for r in (self.api.cluster.resources.get(type="vm") or [])]

    def collect_vm_disks(self, vm): 
        return list(vm.get("_vmdks") or [])
