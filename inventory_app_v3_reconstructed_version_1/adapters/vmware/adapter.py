"""
VMware vSphere adapter.

- Reads credentials from self.instance["connection_options"]
  (already decrypted by the collector layer if encrypted).
- Prefers connection_options.ip_address over the host column so the
  collector never depends on DNS resolution of the FQDN.
"""
import logging
import ssl

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from adapters.base import BaseAdapter

logger = logging.getLogger("inventory_app.adapters.vmware")


def _ctx():
    return ssl._create_unverified_context()


SKIP_GUEST_PATH_PREFIXES = (
    "/var/lib/kubelet/",
    "/var/lib/docker/",
    "/run/",
    "/dev/",
    "/sys/",
    "/proc/",
)
MAX_LINUX_DEPTH = 4


def _is_real_partition(path):
    if not path:
        return False
    for prefix in SKIP_GUEST_PATH_PREFIXES:
        if path.startswith(prefix):
            return False
    if path.startswith("/"):
        depth = len([p for p in path.split("/") if p])
        if depth > MAX_LINUX_DEPTH:
            return False
    return True


def _get_datastore_backing(ds_info):
    if ds_info is None:
        return None, None
    if isinstance(ds_info, vim.host.NasDatastoreInfo):
        nas = getattr(ds_info, "nas", None)
        if nas:
            host = getattr(nas, "remoteHost", "")
            path = getattr(nas, "remotePath", "")
            proto = getattr(nas, "type", "NFS")
            bt = "NFS" if "NFS41" not in str(proto).upper() else "NFS4.1"
            return bt, f"{host}:{path}"[:500]
        return "NFS", None
    if isinstance(ds_info, vim.host.VmfsDatastoreInfo):
        vmfs = getattr(ds_info, "vmfs", None)
        if vmfs:
            extents = getattr(vmfs, "extent", []) or []
            if extents:
                dn = getattr(extents[0], "diskName", "") or ""
                if   dn.startswith("naa."):    bt = "VMFS-SAN"
                elif dn.startswith("t10."):    bt = "VMFS-iSCSI"
                elif dn.startswith("eui."):    bt = "VMFS-NVMe"
                elif (dn.startswith("mpx.") or dn.startswith("vmhba")):
                    bt = "VMFS-Local"
                else:                          bt = "VMFS"
                return bt, dn[:500]
        return "VMFS", None
    if isinstance(ds_info, vim.vsan.DatastoreInfo):
        return "vSAN", None
    if hasattr(vim, "VvolDatastoreInfo") and isinstance(ds_info, vim.VvolDatastoreInfo):
        return "VVol", None
    if isinstance(ds_info, vim.host.LocalDatastoreInfo):
        p = getattr(ds_info, "path", None)
        return "Local", (p[:500] if p else None)
    return type(ds_info).__name__.replace("DatastoreInfo", ""), None


def _safe(obj, *attrs, default=None):
    try:
        for a in attrs:
            obj = getattr(obj, a)
            if obj is None:
                return default
        return obj if obj is not None else default
    except (AttributeError, TypeError):
        return default


class VMwareAdapter(BaseAdapter):
    type_key = "vmware"

    def __init__(self, instance):
        super().__init__(instance)
        self.si = None
        self.content = None
        self._cluster_host_map = {}

    @classmethod
    def capabilities(cls):
        return {
            "clusters": True, "hosts": True, "datastores": True, "vms": True,
            "datacenters": True, "vm_disks": True, "vm_nics": True,
            "vm_disk_usage": True,
        }

    # ── connection ──────────────────────────────────────────────────
    def connect(self):
        from credential_crypto import decrypt_options

        opts = decrypt_options(self.instance.get("connection_options") or {})

        # OPTION 3 FIX: prefer the explicit IP from connection_options.
        host = opts.get("ip_address") or self.instance.get("host")
        user = opts.get("username") or self.instance.get("credential_ref")
        password = opts.get("password") or ""
        port = self.instance.get("port") or 443

        if not host:
            raise RuntimeError(f"VMware instance {self.instance_id} has no host set")

        self.si = SmartConnect(host=host, user=user, pwd=password,
                               port=port, sslContext=_ctx())
        self.content = self.si.RetrieveContent()

    def disconnect(self):
        if self.si:
            try:
                Disconnect(self.si)
            except Exception:
                pass
            self.si = None
            self.content = None

    # ── helper ──────────────────────────────────────────────────────
    def _find(self, kind, props):
        view = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [kind], True)
        try:
            objs = list(view.view)
            if not objs:                      # ? ADD THIS
                return []                     # ? ADD THIS
            if not props:
                return [{"obj": o, "props": {}} for o in objs]
            specs = [vim.PropertyCollector.ObjectSpec(obj=o) for o in objs]
            pspec = vim.PropertyCollector.PropertySpec(
                type=kind, all=False, pathSet=props)
            fspec = vim.PropertyCollector.FilterSpec(
                objectSet=specs, propSet=[pspec])
            result = self.content.propertyCollector.RetrieveProperties([fspec])
            return [{"obj": r.obj,
                     "props": {x.name: x.val for x in r.propSet}}
                    for r in result]
        finally:
            view.Destroy()    


    # ── datacenters ─────────────────────────────────────────────────
    def collect_datacenters(self):
        out = []
        for item in self._find(vim.Datacenter, ["name", "vmFolder", "hostFolder"]):
            dc = item["obj"]; p = item["props"]
            out.append({
                "native_id": dc._moId,
                "name": dc.name,
                "extra": {
                    "vm_folder":   p.get("vmFolder").name   if p.get("vmFolder")   else None,
                    "host_folder": p.get("hostFolder").name if p.get("hostFolder") else None,
                    "status":      "Normal",
                },
            })
        return out

    # ── clusters ────────────────────────────────────────────────────
    def collect_clusters(self):
        out = []
        for item in self._find(vim.ClusterComputeResource,
                               ["name", "summary", "configurationEx", "host"]):
            c = item["obj"]; p = item["props"]
            s = p.get("summary"); cx = p.get("configurationEx")
            oid = c._moId

            nh = len(c.host) if c.host else 0
            self._cluster_host_map[c.name] = [h.name for h in c.host] if c.host else []
            nv = sum(len(h.vm) for h in c.host if h.vm) if c.host else 0

            tc = _safe(s, "totalCpu", default=0) or 0
            uc = sum(_safe(h, "summary", "quickStats", "overallCpuUsage", default=0) or 0
                     for h in c.host) if c.host else 0
            fc = tc - uc
            cp = (uc / tc * 100) if tc > 0 else 0

            tm_mb = (_safe(s, "totalMemory", default=0) or 0) / (1024 ** 2)
            um_mb = sum(_safe(h, "summary", "quickStats", "overallMemoryUsage", default=0) or 0
                        for h in c.host) if c.host else 0
            fm_mb = tm_mb - um_mb
            mp = (um_mb / tm_mb * 100) if tm_mb > 0 else 0

            ts = fs = 0.0; seen = set()
            if c.host:
                for h in c.host:
                    if h.datastore:
                        for ds in h.datastore:
                            seen.add(ds)
            for ds in seen:
                if ds.summary and hasattr(ds.summary, "capacity"):
                    ts += (ds.summary.capacity  or 0) / (1024 ** 3)
                    fs += (ds.summary.freeSpace or 0) / (1024 ** 3)
            us = ts - fs
            sp = (us / ts * 100) if ts > 0 else 0

            nc = nt = 0
            if c.host:
                for h in c.host:
                    if h.hardware and h.hardware.cpuInfo:
                        nc += getattr(h.hardware.cpuInfo, "numCpuCores", 0) or 0
                        nt += getattr(h.hardware.cpuInfo, "numCpuThreads", 0) or 0

            ha = drs = dpm = False
            if cx:
                ha  = getattr(getattr(cx, "dasConfig", None), "enabled", False)
                drs = getattr(getattr(cx, "drsConfig", None), "enabled", False)
                dpm = getattr(getattr(cx, "dpmConfig", None), "enabled", False)

            out.append({
                "native_id": oid,
                "name": c.name,
                "num_hosts": nh, "num_vms": nv,
                "cpu_total_mhz": tc, "cpu_used_mhz": uc, "cpu_free_mhz": fc,
                "cpu_usage_percent": round(cp, 2),
                "num_cpu_cores": nc, "num_cpu_threads": nt,
                "memory_total_mb": round(tm_mb, 2),
                "memory_used_mb":  round(um_mb, 2),
                "memory_free_mb":  round(fm_mb, 2),
                "memory_usage_percent": round(mp, 2),
                "storage_total_gb": round(ts, 2),
                "storage_used_gb":  round(us, 2),
                "storage_free_gb":  round(fs, 2),
                "storage_usage_percent": round(sp, 2),
                "ha_enabled":  ha,
                "drs_enabled": drs,
                "config_status": "Normal",
                "overall_status": str(_safe(s, "overallStatus", default="N/A")),
                "extra": {"dpm_enabled": dpm},
            })
        return out

    # ── hosts ───────────────────────────────────────────────────────
    def collect_hosts(self):
        out = []
        for item in self._find(vim.HostSystem,
                               ["name", "summary", "hardware",
                                "parent", "runtime", "config",
                                "hardware.cpuPkg"]):
            h = item["obj"]; p = item["props"]
            s = p.get("summary"); hw = p.get("hardware")
            pa = p.get("parent"); rt = p.get("runtime"); cfg = p.get("config")
            oid = h._moId

            cn = dn = None
            t = pa
            while t:
                if isinstance(t, vim.ClusterComputeResource): cn = t.name
                if isinstance(t, vim.Datacenter):             dn = t.name
                t = getattr(t, "parent", None)

            ip = "N/A"
            if s and getattr(s, "config", None) and getattr(s.config, "ipAddress", None):
                ip = s.config.ipAddress or "N/A"
            if ip == "N/A" and cfg and getattr(cfg, "network", None) and cfg.network.vnic:
                for v in cfg.network.vnic:
                    a = _safe(v, "spec", "ip", "ipAddress")
                    if a and a != "0.0.0.0":
                        ip = a; break

            vendor = _safe(hw, "systemInfo", "vendor", default="N/A") or "N/A"
            model  = _safe(hw, "systemInfo", "model",  default="N/A") or "N/A"

            ci = getattr(hw, "cpuInfo", None)
            cm = "N/A"
            cpkg = p.get("hardware.cpuPkg")
            if cpkg and len(cpkg) > 0:
                cm = getattr(cpkg[0], "description", None) or "N/A"
            if cm == "N/A" and ci:
                cm = (getattr(ci, "cpuModel", None)
                      or getattr(ci, "modelName", "N/A") or "N/A")

            cc = getattr(ci, "numCpuCores", 0) or 0
            ct = getattr(ci, "numCpuThreads", 0) or 0
            mhz = int(ci.hz / 1_000_000) if ci and getattr(ci, "hz", None) else 0

            mt_gb = (hw.memorySize / (1024 ** 3)) if hw and getattr(hw, "memorySize", None) else 0
            mu_gb = 0
            if s and getattr(s, "quickStats", None):
                mr = getattr(s.quickStats, "overallMemoryUsage", None)
                mu_gb = (mr / 1024) if mr is not None else 0

            pst = str(rt.powerState) if rt and getattr(rt, "powerState", None) else "N/A"
            cst = str(rt.connectionState) if rt and getattr(rt, "connectionState", None) else "N/A"
            mm  = "Yes" if rt and getattr(rt, "inMaintenanceMode", False) else "No"

            ev = eb = "N/A"
            if s and getattr(s, "config", None) and getattr(s.config, "product", None):
                ev = getattr(s.config.product, "version", "N/A") or "N/A"
                eb = str(getattr(s.config.product, "build", "N/A") or "N/A")

            out.append({
                "native_id": oid, "name": h.name,
                "cluster_name": cn,
                "datacenter_name": dn,
                "ip_address": ip, "vendor": vendor, "model": model,
                "cpu_model": cm, "cpu_cores": cc, "cpu_threads": ct, "cpu_mhz": mhz,
                "memory_total_mb": round(mt_gb * 1024, 2),
                "memory_used_mb":  round(mu_gb * 1024, 2),
                "power_state": pst, "connection_state": cst,
                "maintenance_mode": 1 if mm == "Yes" else 0,
                "os_name": "ESXi", "os_version": ev,
                "extra": {"esxi_build": eb},
            })
        return out

    # ── datastores ──────────────────────────────────────────────────
    def collect_datastores(self):
        out = []
        for item in self._find(vim.Datastore,
                               ["name", "summary", "host", "vm", "info"]):
            ds = item["obj"]; p = item["props"]
            s = p.get("summary"); info = p.get("info")
            oid = ds._moId

            cap_gb = (s.capacity / (1024 ** 2)) if s and getattr(s, "capacity", None) else 0
            free_gb = (s.freeSpace / (1024 ** 2)) if s and getattr(s, "freeSpace", None) else 0
            used_gb = cap_gb - free_gb
            fp = (free_gb / cap_gb * 100) if cap_gb else 0
            ia = bool(getattr(s, "accessible", False)) if s else False
            dt = getattr(s, "type", None) if s else None

            bt, bu = _get_datastore_backing(info)

            hosts = []; cn = None
            if ds.host:
                for hm in ds.host:
                    if hm.key:
                        hn = hm.key.name
                        hosts.append(hn)
                        if not cn:
                            for cl_name, cl_hosts in self._cluster_host_map.items():
                                if hn in cl_hosts:
                                    cn = cl_name
                                    break

            out.append({
                "native_id": oid, "name": ds.name,
                "status": "Normal",
                "accessible": 1 if ia else 0,
                "type": dt,
                "num_vms": len(ds.vm) if ds.vm else 0,
                "capacity_gb": round(cap_gb, 2),
                "used_gb":     round(used_gb, 2),
                "free_gb":     round(free_gb, 2),
                "free_percent": round(fp, 2),
                "provisioned_gb": round(used_gb, 2),
                "thin_savings_gb": None,
                "cluster_name": cn,
                "extra": {
                    "backing_type": bt,
                    "backing_url":  bu,
                    "hosts":        ",".join(hosts[:5]) if hosts else None,
                },
            })
        return out

    # ── VMs ─────────────────────────────────────────────────────────
    def _vm_dict(self, vm, p):
        uuid = p.get("config.instanceUuid") or None
        ist = bool(p.get("config.template", False))
        psr = p.get("runtime.powerState", None)
        ps = str(psr) if psr else "unknown"

        ips = []
        for nic in (p.get("guest.net") or []):
            if getattr(nic, "ipConfig", None):
                for e in (nic.ipConfig.ipAddress or []):
                    a = getattr(e, "ipAddress", None)
                    if (a and a not in ("", "0.0.0.0")
                            and not a.startswith("169.254")
                            and not a.startswith("fe80")
                            and ":" not in a
                            and a not in ips):
                        ips.append(a)
        all_ips = ",".join(ips) if ips else None

        disk_count = 0
        total_disk_gb = 0.0
        vmdks = []
        for dev in (p.get("config.hardware.device") or []):
            if isinstance(dev, vim.vm.device.VirtualDisk):
                disk_count += 1
                sg = 0.0
                if getattr(dev, "capacityInKB", None):
                    sg = round(dev.capacityInKB / (1024 ** 2), 2)
                    total_disk_gb += sg
                fn = getattr(getattr(dev, "backing", None), "fileName", None)
                if fn:
                    vmdks.append({"disk_path": fn, "size_gb": sg})

        partitions = []
        for gd in (p.get("guest.disk") or []):
            gpath = getattr(gd, "diskPath", None)
            cap = getattr(gd, "capacity", 0) or 0
            fre = getattr(gd, "freeSpace", 0) or 0
            if not gpath or cap <= 0:
                continue
            if not _is_real_partition(gpath):
                continue
            cap_gb  = round(cap / (1024 ** 3), 2)
            free_gb = round(fre / (1024 ** 3), 2)
            used_gb = round(cap_gb - free_gb, 2)
            pct     = round(used_gb / cap_gb * 100, 2) if cap_gb > 0 else 0
            partitions.append({
                "partition_path": gpath,
                "capacity_gb": cap_gb,
                "used_gb": used_gb,
                "free_gb": free_gb,
                "usage_percent": pct,
            })

        host_name = vm.runtime.host.name if vm.runtime and vm.runtime.host else None
        cluster_name = None
        if (vm.runtime and vm.runtime.host
                and isinstance(vm.runtime.host.parent, vim.ClusterComputeResource)):
            cluster_name = vm.runtime.host.parent.name

        return {
            "native_id": uuid or f"legacy-{vm._moId}",
            "name": p.get("name", "N/A"),
            "cpu_count": p.get("config.hardware.numCPU", 0) or 0,
            "memory_mb": p.get("config.hardware.memoryMB", 0) or 0,
            "power_state": ps,
            "os_name": p.get("config.guestFullName", "N/A") or "N/A",
            "os_version": None,
            "is_template": 1 if ist else 0,
            "primary_ip": p.get("guest.ipAddress") or None,
            "all_ips": all_ips,
            "dns_servers": None, "default_gateway": None,
            "hostname": None,
            "nic_count": None,
            "disk_count": disk_count,
            "total_disk_gb": round(total_disk_gb, 2),
            "actual_disk_gb": None,
            "tools_version": None,
            "uptime_days": None,
            "app_name": None, "server_owner": None, "business_owner": None,
            "host_name": host_name,
            "cluster_name": cluster_name,
            "extra": {"vm_uuid": uuid},
            "_vmdks": vmdks,
            "_partitions": partitions,
            "_mo_ref": vm,
        }

    def collect_vms(self):
        out = []
        for item in self._find(vim.VirtualMachine, [
            "name",
            "config.instanceUuid",
            "config.hardware.numCPU",
            "config.hardware.memoryMB",
            "config.guestFullName",
            "config.template",
            "guest.ipAddress",
            "guest.net",
            "guest.disk",
            "runtime.powerState",
            "config.hardware.device",
        ]):
            out.append(self._vm_dict(item["obj"], item["props"]))
        return out

    def collect_vm_disks(self, vm):
        return list(vm.get("_vmdks") or [])

    def collect_vm_disk_usage(self, vm):
        return list(vm.get("_partitions") or [])
