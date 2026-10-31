"""
Generic collector service.
For every enabled hypervisor_instance, loads the matching adapter,
runs a collection, and writes to vcenter_inventory_v3.
"""
import json
import logging
import datetime

import pymysql

from adapters import load_adapter
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME

logger = logging.getLogger("inventory_app.collector")


def _db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                           database=DB_NAME, cursorclass=pymysql.cursors.DictCursor,
                           autocommit=False)


def _start_run(cur, instance_id, adapter_version=None):
    cur.execute("""INSERT INTO collection_runs
                     (hypervisor_instance_id, started_at, status, adapter_version)
                   VALUES (%s, NOW(), 'running', %s)""",
                (instance_id, adapter_version))
    return cur.lastrowid


def _finish_run(cur, run_id, status, counts, error=None):
    cur.execute("""UPDATE collection_runs
                      SET finished_at=NOW(), status=%s,
                          clusters_collected=%s, hosts_collected=%s,
                          vms_collected=%s, datastores_collected=%s,
                          error_count=%s, error_summary=%s
                    WHERE id=%s""",
                (status, counts.get("clusters", 0), counts.get("hosts", 0),
                 counts.get("vms", 0), counts.get("datastores", 0),
                 0 if not error else 1, error, run_id))


# ── inserters — direct column mapping ───────────────────────────────────
def _insert_datacenters(cur, iid, run_id, rows):
    for d in rows:
        cur.execute("""INSERT INTO datacenters
            (hypervisor_instance_id, run_id, native_id, name, extra)
            VALUES (%s, %s, %s, %s, %s)""",
            (iid, run_id, d["native_id"], d["name"],
             json.dumps(d.get("extra") or {})))


def _insert_clusters(cur, iid, run_id, rows):
    for c in rows:
        cur.execute("""INSERT INTO clusters
            (hypervisor_instance_id, run_id, native_id, name, num_hosts, num_vms,
             cpu_total_mhz, cpu_used_mhz, cpu_free_mhz, cpu_usage_percent,
             num_cpu_cores, num_cpu_threads,
             memory_total_mb, memory_used_mb, memory_free_mb, memory_usage_percent,
             storage_total_gb, storage_used_gb, storage_free_gb, storage_usage_percent,
             ha_enabled, drs_enabled, config_status, overall_status, extra)
            VALUES (%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s, %s,%s,%s,%s,
                    %s,%s,%s,%s, %s,%s,%s,%s,%s)""",
            (iid, run_id, c["native_id"], c["name"],
             c.get("num_hosts"), c.get("num_vms"),
             c.get("cpu_total_mhz"), c.get("cpu_used_mhz"), c.get("cpu_free_mhz"),
             c.get("cpu_usage_percent"),
             c.get("num_cpu_cores"), c.get("num_cpu_threads"),
             c.get("memory_total_mb"), c.get("memory_used_mb"), c.get("memory_free_mb"),
             c.get("memory_usage_percent"),
             c.get("storage_total_gb"), c.get("storage_used_gb"),
             c.get("storage_free_gb"), c.get("storage_usage_percent"),
             c.get("ha_enabled"), c.get("drs_enabled"),
             c.get("config_status"), c.get("overall_status"),
             json.dumps(c.get("extra") or {})))


def _insert_hosts(cur, iid, run_id, rows, cluster_map):
    """cluster_map: {name: native_id}"""
    for h in rows:
        cn = h.get("cluster_name")
        cluster_native_id = cluster_map.get(cn) if cn else None
        cur.execute("""INSERT INTO hosts
            (hypervisor_instance_id, run_id, cluster_native_id, datacenter_name,
             native_id, name, ip_address, vendor, model, cpu_model,
             cpu_cores, cpu_threads, cpu_mhz,
             memory_total_mb, memory_used_mb, power_state, connection_state,
             maintenance_mode, os_name, os_version, extra)
            VALUES (%s,%s,%s,%s, %s,%s,%s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s,
                    %s,%s,%s,%s)""",
            (iid, run_id, cluster_native_id, h.get("datacenter_name"),
             h["native_id"], h["name"], h.get("ip_address"),
             h.get("vendor"), h.get("model"), h.get("cpu_model"),
             h.get("cpu_cores"), h.get("cpu_threads"), h.get("cpu_mhz"),
             h.get("memory_total_mb"), h.get("memory_used_mb"),
             h.get("power_state"), h.get("connection_state"),
             h.get("maintenance_mode"),
             h.get("os_name"), h.get("os_version"),
             json.dumps(h.get("extra") or {})))


def _insert_datastores(cur, iid, run_id, rows, cluster_map):
    for d in rows:
        cn = d.get("cluster_name")
        cluster_native_id = cluster_map.get(cn) if cn else None
        cur.execute("""INSERT INTO datastores
            (hypervisor_instance_id, run_id, cluster_native_id, native_id, name,
             status, `accessible`, type, num_vms,
             capacity_gb, used_gb, free_gb, free_percent,
             provisioned_gb, thin_savings_gb, extra)
            VALUES (%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s)""",
            (iid, run_id, cluster_native_id, d["native_id"], d["name"],
             d.get("status"), d.get("accessible"), d.get("type"), d.get("num_vms"),
             d.get("capacity_gb"), d.get("used_gb"), d.get("free_gb"),
             d.get("free_percent"),
             d.get("provisioned_gb"), d.get("thin_savings_gb"),
             json.dumps(d.get("extra") or {})))


def _insert_vms(cur, iid, run_id, rows, cluster_map, host_map, adapter):
    """
    1. INSERT all VM rows, keep {src_idx -> new vm_id} mapping
    2. INSERT vm_disks (cross-VM shared detection)
    3. INSERT vm_disk_usage
    """
    vmid_map = {}   # (native_id or fallback) -> new vms.id

    for v in rows:
        cn = v.get("cluster_name")
        hn = v.get("host_name")
        cur.execute("""INSERT INTO vms
            (hypervisor_instance_id, run_id, cluster_native_id, host_native_id,
             native_id, name, cpu_count, memory_mb, power_state,
             os_name, os_version, is_template, primary_ip, all_ips,
             dns_servers, default_gateway, hostname, nic_count, disk_count,
             total_disk_gb, actual_disk_gb, tools_version, uptime_days,
             app_name, server_owner, business_owner, extra,
             legacy_source, legacy_id)
            VALUES (%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s,%s,
                    %s,%s,%s,%s, %s,%s,%s,%s, %s,%s)""",
            (iid, run_id,
             cluster_map.get(cn) if cn else None,
             host_map.get(hn)    if hn else None,
             v["native_id"], v["name"],
             v.get("cpu_count"), v.get("memory_mb"), v.get("power_state"),
             v.get("os_name"), v.get("os_version"), v.get("is_template"),
             v.get("primary_ip"), v.get("all_ips"),
             v.get("dns_servers"), v.get("default_gateway"), v.get("hostname"),
             v.get("nic_count"), v.get("disk_count"),
             v.get("total_disk_gb"), v.get("actual_disk_gb"),
             v.get("tools_version"), v.get("uptime_days"),
             v.get("app_name"), v.get("server_owner"), v.get("business_owner"),
             json.dumps(v.get("extra") or {}),
             None, None))
        vmid_map[id(v)] = cur.lastrowid

    # ── VMDK cross-VM shared disk detection ──
    path_to_rows = {}   # disk_path -> [(new_vm_id, vm_name, size_gb)]
    for v in rows:
        vid = vmid_map.get(id(v))
        if not vid: continue
        for d in (v.get("_vmdks") or []):
            fn = d.get("disk_path")
            if not fn: continue
            path_to_rows.setdefault(fn, []).append((vid, v["name"], d.get("size_gb", 0)))

    disk_inserted = 0
    for fn, users in path_to_rows.items():
        is_shared = 1 if len(users) > 1 else 0
        count = len(users)
        for vid, vm_name, sg in users:
            others = (",".join(n for _, n, _ in users if _ != vm_name)[:1000]
                      if is_shared else None)
            cur.execute("""INSERT INTO vm_disks
                (vm_id, run_id, hypervisor_instance_id, disk_path, size_gb,
                 is_shared, shared_vm_count, extra)
                VALUES (%s,%s,%s,%s,%s, %s,%s,%s)""",
                (vid, run_id, iid, fn, sg, is_shared, count,
                 json.dumps({"shared_vm_names": others}) if is_shared else None))
            disk_inserted += 1

    # ── vm_disk_usage ──
    du_inserted = 0
    for v in rows:
        vid = vmid_map.get(id(v))
        if not vid: continue
        for p in (v.get("_partitions") or []):
            cur.execute("""INSERT INTO vm_disk_usage
                (vm_id, run_id, hypervisor_instance_id,
                 partition_path, capacity_gb, used_gb, free_gb, usage_percent)
                VALUES (%s,%s,%s, %s,%s,%s,%s,%s)""",
                (vid, run_id, iid, p["partition_path"], p["capacity_gb"],
                 p["used_gb"], p["free_gb"], p["usage_percent"]))
            du_inserted += 1

    return len(rows), disk_inserted, du_inserted


# ── main loop ───────────────────────────────────────────────────────────
def collect_instance(instance_id):
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute("""SELECT hi.*, ht.type_key, ht.adapter_version
                         FROM hypervisor_instances hi
                         JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
                        WHERE hi.id = %s""", (instance_id,))
        inst = cur.fetchone()
        if not inst:
            raise RuntimeError(f"hypervisor_instance {instance_id} not found")
        if isinstance(inst.get("connection_options"), str):
            inst["connection_options"] = json.loads(inst["connection_options"] or "{}")

        run_id = _start_run(cur, instance_id, inst.get("adapter_version"))
        conn.commit()

        adapter = load_adapter(inst["type_key"], inst)
        counts = {"clusters": 0, "hosts": 0, "datastores": 0, "vms": 0,
                  "disks": 0, "partitions": 0}
        error_text = None
        status = "success"

        try:
            adapter.connect()

            # 1. datacenters
            try:
                datacenters = adapter.collect_datacenters()
            except NotImplementedError:
                datacenters = []
            except Exception as e:
                logger.warning("datacenters collection failed: %s", e)
                datacenters = []
            _insert_datacenters(cur, instance_id, run_id, datacenters)

            # 2. clusters
            clusters = adapter.collect_clusters()
            _insert_clusters(cur, instance_id, run_id, clusters)
            cluster_map = {c["name"]: c["native_id"] for c in clusters}

            # 3. hosts
            hosts = adapter.collect_hosts()
            _insert_hosts(cur, instance_id, run_id, hosts, cluster_map)
            host_map = {h["name"]: h["native_id"] for h in hosts}

            # 4. datastores
            datastores = adapter.collect_datastores()
            _insert_datastores(cur, instance_id, run_id, datastores, cluster_map)

            # 5. VMs + children
            vms = adapter.collect_vms()
            n_vms, n_disks, n_parts = _insert_vms(
                cur, instance_id, run_id, vms, cluster_map, host_map, adapter)

            counts["clusters"]   = len(clusters)
            counts["hosts"]      = len(hosts)
            counts["datastores"] = len(datastores)
            counts["vms"]        = n_vms
            counts["disks"]      = n_disks
            counts["partitions"] = n_parts

            cur.execute("""UPDATE hypervisor_instances
                             SET last_sync_at=NOW(), last_sync_status='success'
                           WHERE id=%s""", (instance_id,))

        except Exception as e:
            status = "failed"
            error_text = str(e)[:2000]
            logger.exception("Collection failed for instance %s", instance_id)
            cur.execute("""UPDATE hypervisor_instances
                             SET last_sync_at=NOW(), last_sync_status='failed'
                           WHERE id=%s""", (instance_id,))
        finally:
            try: adapter.disconnect()
            except Exception: pass

        _finish_run(cur, run_id, status, counts, error_text)
        conn.commit()
        return {"instance_id": instance_id, "run_id": run_id,
                "status": status, **counts}
    finally:
        conn.close()


def collect_all_enabled():
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM hypervisor_instances "
                    "WHERE enabled=1 AND deleted_at IS NULL ORDER BY id")
        ids = [r["id"] for r in cur.fetchall()]
    finally:
        conn.close()

    results = []
    for iid in ids:
        try:
            results.append(collect_instance(iid))
        except Exception as e:
            logger.exception("Instance %s crashed", iid)
            results.append({"instance_id": iid, "status": "crashed", "error": str(e)})
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(collect_all_enabled(), indent=2, default=str))
