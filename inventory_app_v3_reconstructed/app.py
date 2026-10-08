"""
vCenter / Hyper-V inventory dashboard — Flask app.

Migrated to the normalized schema (vcenter_inventory_v3).

This revision consolidates:

  • Migration to hypervisor_instances / hypervisor_types / collection_runs
    and the unified per-run tables (clusters, hosts, datastores, vms,
    vm_disks, vm_nics, vm_disk_usage).

  • Performance fixes:
      - get_unified_runs() deduplicates by legacy_run_id
      - _get_hosts_data / _get_datastores_data use LEFT JOINs (no N+1)
      - get_unified_vms() uses a lightweight COUNT(*) and pre-aggregated joins
      - /api/dashboard_sites hits base tables directly with WHERE run_id IN (...)
        instead of the summary views

  • Admin endpoints for hypervisor types and instances:
      - CRUD + soft-disable + soft-retire + restore + live connection test
      - Type CRUD with refusal to disable while live instances remain

  • enabled / deleted_at filters applied to:
      - get_latest_run_ids()
      - _new_run_ids()
      - /api/vcenters
      - /api/reporting/environments_list
      - /api/dashboard_sites
    so disabling or retiring an instance hides it everywhere.

  • site_code column on hypervisor_instances drives the dashboard's
    per-site grouping (no more hardcoded SITE_MAP in the frontend).
"""
from flask import Flask, jsonify, request, render_template, session, redirect, url_for, Response, stream_with_context
from credential_crypto import encrypt_options, decrypt_options, is_encrypted
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from decimal import Decimal
import logging
import subprocess
import pymysql
import os
import io
import json
import uuid
import threading
import time
import csv
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression
import joblib

import config
import lifecycle
import export_utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("inventory_app")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
csrf = CSRFProtect(app)

PLAYBOOK_CREATE_VM_VMWARE = config.PLAYBOOK_CREATE_VM_VMWARE
PLAYBOOK_CREATE_VM_HYPERV = config.PLAYBOOK_CREATE_VM_HYPERV
PLAYBOOK_CREATE_VM        = PLAYBOOK_CREATE_VM_VMWARE

vm_jobs = {}
MODEL_DIR = config.MODEL_DIR
os.makedirs(MODEL_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────
#  AUTH DECORATORS
# ─────────────────────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def superadmin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "superadmin":
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated_function


# ─────────────────────────────────────────────────────────────
#  DB
# ─────────────────────────────────────────────────────────────
def get_db_connection():
    return pymysql.connect(
        host=config.DB_HOST, user=config.DB_USER, password=config.DB_PASSWORD,
        database=config.DB_NAME, cursorclass=pymysql.cursors.DictCursor,
        autocommit=True)


def to_float(v):
    if v is None: return 0.0
    if isinstance(v, Decimal): return float(v)
    try: return float(v)
    except (TypeError, ValueError): return 0.0


# ─────────────────────────────────────────────────────────────
#  RUN RESOLUTION
#  Both helpers filter on enabled=1 AND deleted_at IS NULL AND ht.enabled=1
#  so disabling an instance hides it everywhere without deleting anything.
# ─────────────────────────────────────────────────────────────
def get_latest_run_ids():
    """Latest legacy run id per platform (only from live instances)."""
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT MAX(cr.legacy_run_id) AS max_run
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ht.type_key = 'vmware'
           AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
    """)
    vmware = cur.fetchone()["max_run"]
    cur.execute("""
        SELECT MAX(cr.legacy_run_id) AS max_run
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ht.type_key = 'hyperv'
           AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
    """)
    hyperv = cur.fetchone()["max_run"]
    cur.close(); conn.close()
    return vmware, hyperv


def _new_run_ids(legacy_vc_id, legacy_hv_id):
    """
    Translate legacy run ids -> the set of collection_runs.id for each
    platform. A single legacy run explodes into N new runs (one per
    instance). Only live instances are considered.
    """
    conn = get_db_connection(); cur = conn.cursor()

    def ids_for(type_key, legacy):
        if legacy:
            cur.execute("""
                SELECT cr.id FROM collection_runs cr
                  JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
                  JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
                 WHERE ht.type_key = %s AND cr.legacy_run_id = %s
                   AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
            """, (type_key, legacy))
        else:
            cur.execute("""
                SELECT cr.id FROM collection_runs cr
                  JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
                  JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
                 WHERE ht.type_key = %s
                   AND cr.legacy_run_id = (
                       SELECT MAX(cr2.legacy_run_id) FROM collection_runs cr2
                         JOIN hypervisor_instances hi2 ON cr2.hypervisor_instance_id = hi2.id
                         JOIN hypervisor_types ht2 ON hi2.hypervisor_type_id = ht2.id
                        WHERE ht2.type_key = %s
                          AND hi2.enabled = 1 AND hi2.deleted_at IS NULL AND ht2.enabled = 1
                   )
                   AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
            """, (type_key, type_key))
        rows = cur.fetchall()
        return [r["id"] for r in rows] or [0]

    vc_ids = ids_for("vmware", legacy_vc_id)
    hv_ids = ids_for("hyperv", legacy_hv_id)
    cur.close(); conn.close()
    return vc_ids, hv_ids


def get_unified_runs():
    """
    Deduplicated by legacy_run_id (one entry per logical run in the
    dropdown), filtered to live instances only.
    """
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT cr.legacy_run_id AS run_id,
               MIN(cr.started_at) AS run_timestamp,
               'VMware' AS platform,
               cr.legacy_run_id AS vmware_run_id,
               NULL AS hyperv_run_id
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ht.type_key = 'vmware' AND cr.legacy_run_id IS NOT NULL
           AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
         GROUP BY cr.legacy_run_id
    """)
    vmware = cur.fetchall()
    cur.execute("""
        SELECT cr.legacy_run_id AS run_id,
               MIN(cr.started_at) AS run_timestamp,
               'Hyper-V' AS platform,
               NULL AS vmware_run_id,
               cr.legacy_run_id AS hyperv_run_id
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ht.type_key = 'hyperv' AND cr.legacy_run_id IS NOT NULL
           AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
         GROUP BY cr.legacy_run_id
    """)
    hyperv = cur.fetchall()
    cur.close(); conn.close()
    all_runs = list(vmware) + list(hyperv)
    all_runs.sort(key=lambda x: x["run_id"] or 0, reverse=True)
    return all_runs


# ─────────────────────────────────────────────────────────────
#  DASHBOARD — direct-table aggregate (no views)
# ─────────────────────────────────────────────────────────────
@app.route("/api/dashboard_sites")
@login_required
def dashboard_sites():
    """
    One query per platform, aggregating directly from base tables with
    WHERE run_id IN (...) filters. Each row carries `site_code` so the
    frontend can group by site without a hardcoded mapping.
    """
    new_vc, new_hv = _new_run_ids(
        request.args.get("run_id_vmware"),
        request.args.get("run_id_hyperv")
    )

    conn = get_db_connection(); cur = conn.cursor()

    def query_platform(type_key, run_ids):
        ph = ",".join(["%s"] * len(run_ids))
        cur.execute(f"""
            SELECT
                hi.name AS resource_name,
                hi.site_code,
                json_unquote(json_extract(hi.connection_options,'$.ip_address')) AS ip_vcenter,
                COALESCE(c.num_clusters, 0)         AS num_clusters,
                COALESCE(c.num_hosts, 0)            AS num_hosts,
                COALESCE(c.total_cpu_mhz, 0)        AS total_cpu_mhz,
                COALESCE(c.used_cpu_mhz, 0)         AS used_cpu_mhz,
                COALESCE(c.free_cpu_mhz, 0)         AS free_cpu_mhz,
                COALESCE(c.num_cpu_cores, 0)        AS num_cpu_cores,
                COALESCE(c.total_memory_mb, 0)      AS total_memory_mb,
                COALESCE(c.used_memory_mb, 0)       AS used_memory_mb,
                COALESCE(c.free_memory_mb, 0)       AS free_memory_mb,
                COALESCE(ds.num_datastores, 0)      AS num_datastores,
                COALESCE(ds.total_storage_gb, 0)    AS total_storage_gb,
                COALESCE(ds.used_storage_gb, 0)     AS used_storage_gb,
                COALESCE(ds.free_storage_gb, 0)     AS free_storage_gb,
                COALESCE(dc.num_datacenters, 0)     AS num_datacenters,
                COALESCE(vm.num_vms, 0)             AS num_vms,
                COALESCE(vm.total_cpu_vms, 0)       AS total_cpu_vms,
                COALESCE(vm.total_memory_vms_mb, 0) AS total_memory_vms_mb,
                COALESCE(vm.total_disk_size_gb, 0)  AS total_disk_size_gb
            FROM hypervisor_instances hi
            JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
            LEFT JOIN (
                SELECT hypervisor_instance_id,
                       COUNT(*)             AS num_clusters,
                       SUM(num_hosts)       AS num_hosts,
                       SUM(cpu_total_mhz)   AS total_cpu_mhz,
                       SUM(cpu_used_mhz)    AS used_cpu_mhz,
                       SUM(cpu_free_mhz)    AS free_cpu_mhz,
                       SUM(num_cpu_cores)   AS num_cpu_cores,
                       SUM(memory_total_mb) AS total_memory_mb,
                       SUM(memory_used_mb)  AS used_memory_mb,
                       SUM(memory_free_mb)  AS free_memory_mb
                  FROM clusters
                 WHERE run_id IN ({ph})
                 GROUP BY hypervisor_instance_id
            ) c  ON c.hypervisor_instance_id  = hi.id
            LEFT JOIN (
                SELECT hypervisor_instance_id,
                       COUNT(*)         AS num_datastores,
                       SUM(capacity_gb) AS total_storage_gb,
                       SUM(used_gb)     AS used_storage_gb,
                       SUM(free_gb)     AS free_storage_gb
                  FROM datastores
                 WHERE run_id IN ({ph})
                 GROUP BY hypervisor_instance_id
            ) ds ON ds.hypervisor_instance_id = hi.id
            LEFT JOIN (
                SELECT hypervisor_instance_id, COUNT(*) AS num_datacenters
                  FROM datacenters
                 WHERE run_id IN ({ph})
                 GROUP BY hypervisor_instance_id
            ) dc ON dc.hypervisor_instance_id = hi.id
            LEFT JOIN (
                SELECT hypervisor_instance_id,
                       COUNT(*)           AS num_vms,
                       SUM(cpu_count)     AS total_cpu_vms,
                       SUM(memory_mb)     AS total_memory_vms_mb,
                       SUM(total_disk_gb) AS total_disk_size_gb
                  FROM vms
                 WHERE run_id IN ({ph})
                 GROUP BY hypervisor_instance_id
            ) vm ON vm.hypervisor_instance_id = hi.id
            WHERE ht.type_key = %s
              AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
              AND (c.num_clusters IS NOT NULL
                   OR ds.num_datastores IS NOT NULL
                   OR dc.num_datacenters IS NOT NULL
                   OR vm.num_vms IS NOT NULL)
        """, list(run_ids) * 4 + [type_key])
        return cur.fetchall()

    vmware_rows = query_platform("vmware", new_vc)
    hyperv_rows = query_platform("hyperv", new_hv)
    cur.close(); conn.close()

    def clean(rows, platform):
        out = []
        for r in rows:
            d = dict(r)
            total_cpu_mhz = float(d.get("total_cpu_mhz") or 0)
            used_cpu_mhz  = float(d.get("used_cpu_mhz")  or 0)
            total_mem_gb  = float(d.get("total_memory_mb") or 0) / 1024
            used_mem_gb   = float(d.get("used_memory_mb")  or 0) / 1024
            free_mem_gb   = float(d.get("free_memory_mb")  or 0) / 1024
            total_stor_gb = float(d.get("total_storage_gb") or 0)
            used_stor_gb  = float(d.get("used_storage_gb")  or 0)
            free_stor_gb  = float(d.get("free_storage_gb")  or 0)
            num_cores     = int(d.get("num_cpu_cores") or 0)

            cpu_pct = (used_cpu_mhz / total_cpu_mhz * 100) if total_cpu_mhz else 0
            mem_pct = (used_mem_gb  / total_mem_gb  * 100) if total_mem_gb  else 0
            sto_pct = (used_stor_gb / total_stor_gb * 100) if total_stor_gb else 0
            used_cores = round(num_cores * cpu_pct / 100) if num_cores else 0

            total_cpu_vms    = int(d.get("total_cpu_vms") or 0)
            total_mem_vms_mb = float(d.get("total_memory_vms_mb") or 0)
            total_disk_gb    = float(d.get("total_disk_size_gb") or 0)

            def _ratio(num, den):
                if not den: return "N/A"
                return f"{round(num / den, 1)}:1"

            out.append({
                "resource_name": d["resource_name"],
                "site_code": d.get("site_code"),
                "ip_vcenter": d.get("ip_vcenter") or "-",
                "platform": platform,
                "num_clusters": int(d.get("num_clusters") or 0),
                "num_hosts": int(d.get("num_hosts") or 0),
                "num_datastores": int(d.get("num_datastores") or 0),
                "num_datacenters": int(d.get("num_datacenters") or 0),
                "num_vms": int(d.get("num_vms") or 0),
                "total_cores": num_cores,
                "used_cores": used_cores,
                "free_cores": max(0, num_cores - used_cores),
                "cpu_usage_percent": round(cpu_pct, 2),
                "total_memory_gb": round(total_mem_gb, 2),
                "used_memory_gb":  round(used_mem_gb, 2),
                "free_memory_gb":  round(free_mem_gb, 2),
                "memory_usage_percent": round(mem_pct, 2),
                "total_storage_gb": round(total_stor_gb, 2),
                "used_storage_gb":  round(used_stor_gb, 2),
                "free_storage_gb":  round(free_stor_gb, 2),
                "storage_usage_percent": round(sto_pct, 2),
                "total_cpu_vms": total_cpu_vms,
                "total_memory_vms_gb": round(total_mem_vms_mb / 1024, 2),
                "total_disk_size_gb": round(total_disk_gb, 2),
                "subscription_cpu_ratio":     _ratio(total_cpu_vms, num_cores),
                "subscription_memory_ratio":  _ratio(total_mem_vms_mb, float(d.get("total_memory_mb") or 0)),
                "subscription_storage_ratio": _ratio(total_disk_gb, total_stor_gb),
            })
        return out

    return jsonify({
        "vmware": clean(vmware_rows, "VMware"),
        "hyperv": clean(hyperv_rows, "Hyper-V"),
    })


# ─────────────────────────────────────────────────────────────
#  SITE AGGREGATION (legacy endpoints — kept for compatibility)
# ─────────────────────────────────────────────────────────────
def get_aggregated_site_data_unified(run_id_vmware=None, run_id_hyperv=None,
                                      site_name=None, vcenter_list=None):
    """Reads summary views. Only live instances are considered."""
    conn = get_db_connection(); cur = conn.cursor()
    latest_vc, latest_hv = get_latest_run_ids()
    run_id_vmware = run_id_vmware or latest_vc
    run_id_hyperv = run_id_hyperv or latest_hv
    data = []

    def _num(v):
        try: return float(v)
        except (TypeError, ValueError): return 0.0

    if vcenter_list:
        ph = ",".join(["%s"] * len(vcenter_list))
        cur.execute(f"""
            SELECT Vcenter AS resource_name, ip_vcenter, num_clusters, num_hosts,
                   num_datastores, num_vms, total_cores, used_cores, free_cores,
                   cpu_usage_percent, total_memory_gb, used_memory_gb, free_memory_gb,
                   memory_usage_percent, total_storage_gb, used_storage_gb,
                   free_storage_gb, storage_usage_percent,
                   Subscription_cpu_ratio AS subscription_cpu_ratio,
                   Subscription_memory_ratio AS subscription_memory_ratio,
                   Subscription_storage_ratio AS subscription_storage_ratio,
                   'VMware' AS platform
              FROM vcenter_summary_all_runs
             WHERE run_id = %s AND Vcenter IN ({ph})
        """, (run_id_vmware, *vcenter_list))
        for row in cur.fetchall():
            data.append({
                "site_name": site_name or "VMware", "platform": "VMware",
                "resource_name": row["resource_name"],
                "ip_vcenter": row["ip_vcenter"] or "-",
                "num_clusters": _num(row["num_clusters"]),
                "num_hosts": _num(row["num_hosts"]),
                "num_datastores": _num(row["num_datastores"]),
                "num_vms": _num(row["num_vms"]),
                "total_cores": _num(row["total_cores"]),
                "used_cores": _num(row["used_cores"]),
                "free_cores": _num(row["free_cores"]),
                "cpu_usage_percent": _num(row["cpu_usage_percent"]),
                "total_memory_gb": _num(row["total_memory_gb"]),
                "used_memory_gb": _num(row["used_memory_gb"]),
                "free_memory_gb": _num(row["free_memory_gb"]),
                "memory_usage_percent": _num(row["memory_usage_percent"]),
                "total_storage_gb": _num(row["total_storage_gb"]),
                "used_storage_gb": _num(row["used_storage_gb"]),
                "free_storage_gb": _num(row["free_storage_gb"]),
                "storage_usage_percent": _num(row["storage_usage_percent"]),
                "subscription_cpu_ratio": row["subscription_cpu_ratio"] or "N/A",
                "subscription_memory_ratio": row["subscription_memory_ratio"] or "N/A",
                "subscription_storage_ratio": row["subscription_storage_ratio"] or "N/A",
            })

    hyperv_site_map = {
        "B7": ["TE-HXCLOUD", "HVUCSX22"],
        "DR": ["HVMXDR-CLUS", "HVDR-EXCHCLUS"],
        "B90": [],
        "TESTDEV": ["HV-UCSX"],
    }
    hyperv_cluster_list = hyperv_site_map.get(site_name, [])
    if hyperv_cluster_list:
        ph = ",".join(["%s"] * len(hyperv_cluster_list))
        cur.execute(f"""
            SELECT Cluster AS resource_name, cluster_ip, num_hosts, num_datastores,
                   num_vms, total_cores, used_cores, free_cores, cpu_usage_percent,
                   total_memory_gb, used_memory_gb, free_memory_gb, memory_usage_percent,
                   total_storage_gb, used_storage_gb, free_storage_gb,
                   storage_usage_percent,
                   Subscription_cpu_ratio AS subscription_cpu_ratio,
                   Subscription_memory_ratio AS subscription_memory_ratio,
                   Subscription_storage_ratio AS subscription_storage_ratio,
                   'Hyper-V' AS platform
              FROM hyperv_summary_all_runs
             WHERE run_id = %s AND Cluster IN ({ph})
        """, (run_id_hyperv, *hyperv_cluster_list))
        for row in cur.fetchall():
            data.append({
                "site_name": site_name or "Hyper-V", "platform": "Hyper-V",
                "resource_name": row["resource_name"],
                "ip_vcenter": row["cluster_ip"] or "-",
                "num_clusters": 1,
                "num_hosts": _num(row["num_hosts"]),
                "num_datastores": _num(row["num_datastores"]),
                "num_vms": _num(row["num_vms"]),
                "total_cores": _num(row["total_cores"]),
                "used_cores": _num(row["used_cores"]),
                "free_cores": _num(row["free_cores"]),
                "cpu_usage_percent": _num(row["cpu_usage_percent"]),
                "total_memory_gb": _num(row["total_memory_gb"]),
                "used_memory_gb": _num(row["used_memory_gb"]),
                "free_memory_gb": _num(row["free_memory_gb"]),
                "memory_usage_percent": _num(row["memory_usage_percent"]),
                "total_storage_gb": _num(row["total_storage_gb"]),
                "used_storage_gb": _num(row["used_storage_gb"]),
                "free_storage_gb": _num(row["free_storage_gb"]),
                "storage_usage_percent": _num(row["storage_usage_percent"]),
                "subscription_cpu_ratio": row["subscription_cpu_ratio"] or "N/A",
                "subscription_memory_ratio": row["subscription_memory_ratio"] or "N/A",
                "subscription_storage_ratio": row["subscription_storage_ratio"] or "N/A",
            })
    cur.close(); conn.close()
    return data


# ─────────────────────────────────────────────────────────────
#  VM LIST (fast count + pre-aggregated joins)
# ─────────────────────────────────────────────────────────────
def _build_vm_where(run_id_vmware, run_id_hyperv, vcenter_list, host_name,
                    cluster_name, search_term, platform, power_state,
                    is_template, bulk_terms):
    new_vc, new_hv = _new_run_ids(run_id_vmware, run_id_hyperv)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    where = [f"((ht.type_key='vmware' AND v.run_id IN ({vc_ph})) "
             f"OR (ht.type_key='hyperv' AND v.run_id IN ({hv_ph})))"]
    params = list(new_vc) + list(new_hv)

    if platform == "vmware":
        where.append("ht.type_key = 'vmware'")
    elif platform == "hyper-v":
        where.append("ht.type_key = 'hyperv'")

    if vcenter_list:
        ph = ",".join(["%s"] * len(vcenter_list))
        where.append(f"hi.name IN ({ph})")
        params.extend(vcenter_list)

    if host_name:
        where.append("v.host_native_id = %s")
        params.append(host_name)

    if cluster_name:
        where.append("v.cluster_native_id = %s")
        params.append(cluster_name)

    if search_term and not bulk_terms:
        like = f"%{search_term}%"
        where.append("(v.name LIKE %s OR v.primary_ip LIKE %s OR v.all_ips LIKE %s OR v.os_name LIKE %s)")
        params.extend([like, like, like, like])

    if bulk_terms:
        clauses = []
        for term in bulk_terms:
            clauses.append("(v.name=%s OR v.primary_ip=%s OR v.all_ips LIKE %s OR v.all_ips LIKE %s OR v.all_ips LIKE %s)")
            params.extend([term, term, term, f"{term},%", f"%,{term}"])
        where.append("(" + " OR ".join(clauses) + ")")

    if power_state == "on":
        where.append("v.power_state IN ('poweredOn','Running')")
    elif power_state == "off":
        where.append("v.power_state IN ('poweredOff','Off')")

    if is_template == "yes":
        where.append("v.is_template = 1")
    elif is_template == "no":
        where.append("(v.is_template = 0 OR v.is_template IS NULL)")

    return " AND ".join(where), params


def get_unified_vms(run_id_vmware=None, run_id_hyperv=None, vcenter_list=None,
                    host_name=None, cluster_name=None, search_term=None,
                    platform=None, power_state=None, is_template=None,
                    bulk_terms=None, page=1, per_page=100):
    conn = get_db_connection(); cur = conn.cursor()
    where_sql, params = _build_vm_where(
        run_id_vmware, run_id_hyperv, vcenter_list, host_name, cluster_name,
        search_term, platform, power_state, is_template, bulk_terms)

    cur.execute(f"""
        SELECT COUNT(*) AS total
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE {where_sql}
    """, params)
    total = cur.fetchone()["total"]

    offset = (page - 1) * per_page
    cur.execute(f"""
        SELECT v.name AS vm_name,
               v.cpu_count AS cpu,
               v.memory_mb AS ram_mb,
               v.os_name AS os,
               v.primary_ip AS ip_address,
               v.all_ips,
               v.is_template,
               v.power_state,
               h.name AS host_name,
               c.name AS cluster_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform,
               hi.name AS vcenter_name,
               v.total_disk_gb,
               CASE WHEN ht.type_key='vmware' THEN v.native_id ELSE NULL END AS vm_uuid,
               COALESCE(dc.disk_count, 0) AS disk_count
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN hosts h
                 ON h.hypervisor_instance_id = v.hypervisor_instance_id
                AND h.run_id = v.run_id
                AND h.native_id = v.host_native_id
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = v.hypervisor_instance_id
                AND c.run_id = v.run_id
                AND c.native_id = v.cluster_native_id
          LEFT JOIN (
              SELECT vm_id, COUNT(*) AS disk_count FROM vm_disks GROUP BY vm_id
          ) dc ON dc.vm_id = v.id
         WHERE {where_sql}
         ORDER BY platform, vm_name
         LIMIT %s OFFSET %s
    """, params + [per_page, offset])
    rows = cur.fetchall()
    cur.close(); conn.close()
    return {"data": rows, "total": total, "page": page, "per_page": per_page,
            "pages": (total + per_page - 1) // per_page}


def _parse_common_args(args):
    vcenter = args.get("vcenter")
    host = args.get("host")
    cluster = args.get("cluster")
    run_id_vmware = args.get("run_id_vmware")
    run_id_hyperv = args.get("run_id_hyperv")
    q = args.get("q", "").strip()
    bulk_q = args.get("bulk_q", "").strip()
    vcenter_list = vcenter.split(",") if vcenter else None

    platform = args.get("platform", "").strip().lower() or None
    if platform not in ("vmware", "hyper-v"):
        platform = None

    power_state = args.get("power_state", "").strip().lower() or None
    if power_state in ("poweredon", "running"): power_state = "on"
    if power_state in ("poweredoff", "off"):    power_state = "off"
    if power_state not in ("on", "off"):        power_state = None

    is_template = args.get("is_template", "").strip().lower() or None
    if is_template not in ("yes", "no"):
        is_template = None

    bulk_terms = [t.strip() for t in bulk_q.split(",") if t.strip()] if bulk_q else []
    return (run_id_vmware, run_id_hyperv, vcenter_list,
            host, cluster, q, platform, power_state, is_template, bulk_terms)


# ─────────────────────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def home():
    return render_template("new_dashborad.html")


@app.route("/dashboard")
@login_required
def dashboard_page():
    return redirect("dashborad.html")


@app.route("/hosts")
@login_required
def hosts_page():
    return render_template("hosts.html")


@app.route("/clusters")
@login_required
def clusterss_page():
    return render_template("clusters.html")


@app.route("/vcenters")
@login_required
def vcenters_page():
    return render_template("vcenters.html")


@app.route("/vms")
@login_required
def vms_page():
    return render_template("vms.html")


@app.route("/datastore_vms")
@login_required
def datastore_vms_page():
    return render_template("datastore_vms.html")


@app.route("/datastores")
@login_required
def datastores_page():
    return render_template("datastores.html")


@app.route("/health")
@login_required
def health():
    return jsonify({"status": "OK"})


@app.route("/admin")
@login_required
@superadmin_required
def admin_page():
    return render_template("admin.html")


@app.route("/create_vm", methods=["GET"])
@login_required
def create_vm_page():
    return render_template("create_vm.html")


# ─────────────────────────────────────────────────────────────
#  LOGIN / LOGOUT
# ─────────────────────────────────────────────────────────────
from ldap3 import Server, Connection, ALL

LDAP_SERVER = config.LDAP_SERVER
LDAP_REALM = config.LDAP_REALM


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        authenticated = False
        role = "user"
        user_id = None

        if username and password:
            try:
                server = Server(LDAP_SERVER, get_info=ALL)
                conn = Connection(server, user=f"{username}@{LDAP_REALM}",
                                   password=password, auto_bind=True)
                conn.unbind()
                authenticated = True
                logger.info("LDAP login success: %s", username)
            except Exception as e:
                logger.info("LDAP login failed for %s: %s", username, e)

            if not authenticated:
                conn_db = get_db_connection(); cur = conn_db.cursor()
                cur.execute("SELECT * FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
                cur.close(); conn_db.close()
                if user and check_password_hash(user["password_hash"], password):
                    authenticated = True
                    user_id = user["id"]
                    role = user["role"]
                    logger.info("Local DB login success: %s", username)

        if authenticated:
            if user_id is None:
                conn_db = get_db_connection(); cur = conn_db.cursor()
                cur.execute("SELECT id, role FROM users WHERE username=%s", (username,))
                existing = cur.fetchone()
                if existing:
                    user_id = existing["id"]; role = existing["role"]
                else:
                    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                                (username, generate_password_hash(uuid.uuid4().hex), "user"))
                    user_id = cur.lastrowid
                cur.close(); conn_db.close()

            session.clear()
            session["user_id"] = user_id
            session["username"] = username
            session["role"] = role
            session["logged_in"] = True
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────
#  USER MANAGEMENT
# ─────────────────────────────────────────────────────────────
@app.route("/api/create_user", methods=["POST"])
@login_required
@superadmin_required
def create_user():
    data = request.json
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                (data["username"], generate_password_hash(data["password"]), data["role"]))
    cur.close(); conn.close()
    return jsonify({"status": "user created"})


@app.route("/api/list_users")
@login_required
@superadmin_required
def list_users():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT id, username, role, created_at FROM users ORDER BY id DESC")
    data = cur.fetchall()
    cur.close(); conn.close()
    for r in data:
        if r.get("created_at"): r["created_at"] = str(r["created_at"])
    return jsonify(data)


@app.route("/api/delete_user/<int:user_id>", methods=["DELETE"])
@login_required
@superadmin_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        return jsonify({"status": "error", "message": "Cannot delete your own account"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    cur.close(); conn.close()
    return jsonify({"status": "deleted"})


@app.route("/api/change_password", methods=["POST"])
@login_required
@superadmin_required
def change_password():
    data = request.json
    user_id = data.get("user_id")
    new_pass = (data.get("password") or "").strip()
    if not new_pass or len(new_pass) < 6:
        return jsonify({"status": "error", "message": "Password must be at least 6 characters"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                (generate_password_hash(new_pass), user_id))
    cur.close(); conn.close()
    return jsonify({"status": "updated"})


# ─────────────────────────────────────────────────────────────
#  ADMIN — hypervisor types & instances
# ─────────────────────────────────────────────────────────────
def _mask_options(opts_json):
    """Return connection_options with secrets replaced by a placeholder."""
    try:
        opts = json.loads(opts_json or "{}")
    except Exception:
        opts = {}
    safe = dict(opts)
    if safe.get("password"):
        safe["password"] = "__SET__"
    if safe.get("token_secret"):
        safe["token_secret"] = "__SET__"
    return safe


@app.route("/api/admin/hypervisor_types", methods=["GET"])
@login_required
@superadmin_required
def admin_list_types():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT ht.*,
               (SELECT COUNT(*) FROM hypervisor_instances hi
                 WHERE hi.hypervisor_type_id = ht.id
                   AND hi.deleted_at IS NULL) AS instance_count
          FROM hypervisor_types ht
         ORDER BY ht.id
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(rows)


@app.route("/api/admin/hypervisor_types", methods=["POST"])
@login_required
@superadmin_required
def admin_create_type():
    data = request.json or {}
    for f in ("type_key", "display_name"):
        if not data.get(f):
            return jsonify({"error": f"Missing required field: {f}"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO hypervisor_types
              (type_key, display_name, adapter_module, adapter_class, adapter_version,
               capabilities, icon, enabled)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["type_key"], data["display_name"],
            data.get("adapter_module"), data.get("adapter_class"),
            data.get("adapter_version", "1.0.0"),
            data.get("capabilities") if isinstance(data.get("capabilities"), str)
                else json.dumps(data.get("capabilities") or {}),
            data.get("icon", "bi-hdd-stack"),
            1 if data.get("enabled", True) else 0,
        ))
        new_id = cur.lastrowid
    except pymysql.err.IntegrityError as e:
        cur.close(); conn.close()
        return jsonify({"error": f"Type key already exists: {e}"}), 409
    cur.close(); conn.close()
    return jsonify({"id": new_id})


@app.route("/api/admin/hypervisor_types/<int:type_id>", methods=["PUT"])
@login_required
@superadmin_required
def admin_update_type(type_id):
    data = request.json or {}
    allowed = ["display_name", "adapter_module", "adapter_class",
               "adapter_version", "icon", "enabled", "capabilities"]
    updates = []
    params = []
    for f in allowed:
        if f in data:
            if f == "capabilities" and not isinstance(data[f], str):
                updates.append(f"{f}=%s"); params.append(json.dumps(data[f]))
            elif f == "enabled":
                updates.append(f"{f}=%s"); params.append(1 if data[f] else 0)
            else:
                updates.append(f"{f}=%s"); params.append(data[f])
    if not updates:
        return jsonify({"error": "No fields to update"}), 400
    params.append(type_id)
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"UPDATE hypervisor_types SET {', '.join(updates)} WHERE id=%s", params)
    cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/hypervisor_types/<int:type_id>", methods=["DELETE"])
@login_required
@superadmin_required
def admin_disable_type(type_id):
    """Soft-disable a type. Refuses if any live instances still use it."""
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT COUNT(*) AS c FROM hypervisor_instances
                    WHERE hypervisor_type_id=%s AND deleted_at IS NULL""", (type_id,))
    if cur.fetchone()["c"] > 0:
        cur.close(); conn.close()
        return jsonify({"error": "Type has live instances. Disable or retire those first."}), 409
    cur.execute("UPDATE hypervisor_types SET enabled=0 WHERE id=%s", (type_id,))
    cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/instances", methods=["GET"])
@login_required
@superadmin_required
def admin_list_instances():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT hi.id, hi.name, hi.host, hi.port, hi.verify_ssl,
               hi.connection_options, hi.site_code, hi.display_order,
               hi.notes, hi.enabled, hi.deleted_at, hi.created_at,
               hi.last_sync_at, hi.last_sync_status,
               hi.hypervisor_type_id,
               ht.type_key, ht.display_name AS type_name
          FROM hypervisor_instances hi
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         ORDER BY ht.type_key, hi.site_code, hi.name
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        r["connection_options"] = _mask_options(r["connection_options"])
        for k in ("created_at", "last_sync_at", "deleted_at"):
            if r.get(k): r[k] = r[k].isoformat()
    return jsonify(rows)


@app.route("/api/admin/instances", methods=["POST"])
@login_required
@superadmin_required
def admin_create_instance():
    data = request.json or {}
    for f in ("name", "host", "hypervisor_type_id"):
        if not data.get(f):
            return jsonify({"error": f"Missing required field: {f}"}), 400

    opts = {}
    if data.get("ip_address"):   opts["ip_address"]   = data["ip_address"]
    if data.get("username"):     opts["username"]     = data["username"]
    if data.get("password"):     opts["password"]     = data["password"]
    if data.get("domain"):       opts["domain"]       = data["domain"]
    if data.get("token_name"):   opts["token_name"]   = data["token_name"]
    if data.get("token_secret"): opts["token_secret"] = data["token_secret"]

    # Encrypt any secret fields before storing
    opts = encrypt_options(opts)

    conn = get_db_connection(); cur = conn.cursor()


    try:
        cur.execute("""
            INSERT INTO hypervisor_instances
              (hypervisor_type_id, name, site_code, host, port, verify_ssl,
               connection_options, notes, enabled, display_order)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["hypervisor_type_id"], data["name"], data.get("site_code"),
            data["host"], data.get("port"),
            1 if data.get("verify_ssl", 1) else 0,
            json.dumps(opts),
            data.get("notes"),
            1 if data.get("enabled", True) else 0,
            int(data.get("display_order") or 0),
        ))
        new_id = cur.lastrowid
    except pymysql.err.IntegrityError as e:
        cur.close(); conn.close()
        return jsonify({"error": f"Instance name already exists: {e}"}), 409
    cur.close(); conn.close()
    return jsonify({"id": new_id})


@app.route("/api/admin/instances/<int:instance_id>", methods=["PUT"])
@login_required
@superadmin_required
def admin_update_instance(instance_id):
    data = request.json or {}
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT connection_options FROM hypervisor_instances WHERE id=%s", (instance_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Instance not found"}), 404

    try:
        existing_opts = json.loads(row["connection_options"] or "{}")
    except Exception:
        existing_opts = {}

    scalar = ["name", "site_code", "host", "port", "notes", "display_order"]
    updates = []
    params = []
    for f in scalar:
        if f in data:
            updates.append(f"{f}=%s"); params.append(data[f])
    if "verify_ssl" in data:
        updates.append("verify_ssl=%s"); params.append(1 if data["verify_ssl"] else 0)
    if "enabled" in data:
        updates.append("enabled=%s"); params.append(1 if data["enabled"] else 0)
    if "hypervisor_type_id" in data:
        updates.append("hypervisor_type_id=%s"); params.append(data["hypervisor_type_id"])
    for k in ("ip_address", "username", "domain", "token_name"):
        if k in data and data[k] is not None:
            existing_opts[k] = data[k]
    for k in ("password", "token_secret"):
        if k in data and data[k] and data[k] != "__SET__":
            existing_opts[k] = data[k]

    # Encrypt everything before storing (no-op for already-encrypted values)
    existing_opts = encrypt_options(existing_opts)

    updates.append("connection_options=%s"); params.append(json.dumps(existing_opts))
    params.append(instance_id)
    cur.execute(f"UPDATE hypervisor_instances SET {', '.join(updates)} WHERE id=%s", params)
    cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/instances/<int:instance_id>/toggle", methods=["POST"])
@login_required
@superadmin_required
def admin_toggle_instance(instance_id):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT enabled FROM hypervisor_instances WHERE id=%s", (instance_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Instance not found"}), 404
    new_val = 0 if row["enabled"] else 1
    cur.execute("UPDATE hypervisor_instances SET enabled=%s WHERE id=%s", (new_val, instance_id))
    cur.close(); conn.close()
    return jsonify({"enabled": new_val})


@app.route("/api/admin/instances/<int:instance_id>", methods=["DELETE"])
@login_required
@superadmin_required
def admin_retire_instance(instance_id):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE hypervisor_instances SET deleted_at=NOW(), enabled=0 WHERE id=%s",
                (instance_id,))
    cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/instances/<int:instance_id>/restore", methods=["POST"])
@login_required
@superadmin_required
def admin_restore_instance(instance_id):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE hypervisor_instances SET deleted_at=NULL, enabled=1 WHERE id=%s",
                (instance_id,))
    cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/instances/<int:instance_id>/test", methods=["POST"])
@login_required
@superadmin_required
def admin_test_instance(instance_id):
    try:
        from adapters import load_adapter
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("""
            SELECT hi.*, ht.type_key
              FROM hypervisor_instances hi
              JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
             WHERE hi.id = %s
        """, (instance_id,))
        inst = cur.fetchone()
        cur.close(); conn.close()
        if not inst:
            return jsonify({"ok": False, "error": "Instance not found"}), 404
        inst["connection_options"] = json.loads(inst["connection_options"] or "{}")
        adapter = load_adapter(inst["type_key"], inst)
        adapter.connect()
        counts = {
            "clusters": len(adapter.collect_clusters()),
            "hosts":    len(adapter.collect_hosts()),
        }
        adapter.disconnect()
        return jsonify({"ok": True, "counts": counts})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ─────────────────────────────────────────────────────────────
#  UNIFIED API
# ─────────────────────────────────────────────────────────────
@app.route("/api/unified/runs")
@login_required
def unified_runs():
    return jsonify({"runs": get_unified_runs()})


@app.route("/api/unified/site/<site_name>")
@login_required
def unified_site_data(site_name):
    run_id_vmware = request.args.get("run_id_vmware")
    run_id_hyperv = request.args.get("run_id_hyperv")
    site_vcenters = {
        "b7": ["HX-VC", "CCB7", "UCSXD2-VC", "UCSXD1-VC"],
        "dr": ["MXDR", "CCDR", "UCSXDR-VC"],
        "b90": ["TED"],
        "testdev": ["HPSM", "HUAWEI"],
    }
    vcenter_list = site_vcenters.get(site_name.lower(), [])
    results = get_aggregated_site_data_unified(run_id_vmware, run_id_hyperv,
                                                site_name.upper(), vcenter_list)
    return jsonify({"data": results, "runs": get_unified_runs(), "site_name": site_name})


# ─────────────────────────────────────────────────────────────
#  VCENTERS
# ─────────────────────────────────────────────────────────────
@app.route("/api/vcenters")
@login_required
def vcenters():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT hi.id AS id, hi.name AS name,
               json_unquote(json_extract(hi.connection_options,'$.ip_address')) AS hostname,
               json_unquote(json_extract(hi.connection_options,'$.ip_address')) AS ip_address,
               ht.type_key AS type
          FROM hypervisor_instances hi
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE hi.deleted_at IS NULL AND hi.enabled = 1 AND ht.enabled = 1
         ORDER BY ht.type_key, hi.name
    """)
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


# ─────────────────────────────────────────────────────────────
#  CLUSTERS
# ─────────────────────────────────────────────────────────────
def _get_clusters_data(args):
    vcenter = args.get("vcenter")
    legacy_vc = args.get("run_id_vmware")
    legacy_hv = args.get("run_id_hyperv")
    new_vc, new_hv = _new_run_ids(legacy_vc, legacy_hv)

    conn = get_db_connection(); cur = conn.cursor()
    filter_names = None
    if vcenter and vcenter.strip() and vcenter.lower() != "all":
        filter_names = [v.strip() for v in vcenter.split(",") if v.strip()]

    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    query = f"""
        SELECT c.name AS cluster_name, hi.name AS vcenter_name,
               dc.name AS datacenter_name,
               c.num_hosts, c.num_vms,
               c.num_cpu_cores AS total_cores, c.num_cpu_threads,
               c.cpu_total_mhz AS total_cpu_mhz,
               c.cpu_used_mhz  AS used_cpu_mhz,
               c.cpu_free_mhz  AS free_cpu_mhz,
               c.cpu_usage_percent,
               c.memory_total_mb AS total_memory_mb,
               c.memory_used_mb  AS used_memory_mb,
               c.memory_free_mb  AS free_memory_mb,
               c.memory_usage_percent,
               c.storage_total_gb AS total_storage_gb,
               c.storage_used_gb  AS used_storage_gb,
               c.storage_free_gb  AS free_storage_gb,
               c.storage_usage_percent,
               c.ha_enabled, c.drs_enabled,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN datacenters dc
                 ON dc.hypervisor_instance_id = hi.id AND dc.run_id = c.run_id
         WHERE ((ht.type_key='vmware' AND c.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND c.run_id IN ({hv_ph})))
    """
    params = list(new_vc) + list(new_hv)
    if filter_names:
        ph = ",".join(["%s"] * len(filter_names))
        query += f" AND hi.name IN ({ph})"
        params.extend(filter_names)
    query += " ORDER BY platform, cluster_name"
    cur.execute(query, params)
    data = cur.fetchall()
    cur.close(); conn.close()
    return data


@app.route("/api/clusters")
@login_required
def get_clusters():
    return jsonify(_get_clusters_data(request.args))


@app.route("/api/clusters/export")
@login_required
def export_clusters():
    data = _get_clusters_data(request.args)
    fmt = request.args.get("format", "csv")
    data = export_utils.rows_with_tb_conversion(
        data,
        mb_fields=["total_memory_mb", "used_memory_mb", "free_memory_mb"],
        gb_fields=["total_storage_gb", "used_storage_gb", "free_storage_gb"],
    )
    return export_utils.build_export_response(data, fmt=fmt,
                                              base_filename="clusters", sheet_name="Clusters")


@app.route("/api/cluster/<path:cluster_name>")
@login_required
def cluster_details(cluster_name):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT c.*, hi.name AS vcenter_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE c.name = %s
         ORDER BY c.run_id DESC
         LIMIT 50
    """, (cluster_name,))
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


# ─────────────────────────────────────────────────────────────
#  HOSTS
# ─────────────────────────────────────────────────────────────
def _get_hosts_data(args):
    vcenter = args.get("vcenter")
    cluster = args.get("cluster")
    legacy_vc = args.get("run_id_vmware")
    legacy_hv = args.get("run_id_hyperv")
    new_vc, new_hv = _new_run_ids(legacy_vc, legacy_hv)

    conn = get_db_connection(); cur = conn.cursor()
    filter_names = None
    if vcenter and vcenter.strip() and vcenter.lower() != "all":
        filter_names = [v.strip() for v in vcenter.split(",") if v.strip()]

    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    query = f"""
        SELECT h.name AS host_name, h.ip_address, h.vendor, h.model, h.cpu_model,
               h.cpu_cores, h.cpu_threads, h.cpu_mhz,
               h.memory_total_mb / 1024 AS memory_total_gb,
               h.memory_used_mb  / 1024 AS memory_used_gb,
               h.power_state, h.connection_state,
               h.os_version AS esxi_version, NULL AS esxi_build,
               h.maintenance_mode,
               c.name AS cluster_name,
               h.datacenter_name, hi.name AS vcenter_name,
               COALESCE(vm_counts.num_vms, 0) AS num_vms,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM hosts h
          JOIN hypervisor_instances hi ON h.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = h.hypervisor_instance_id
                AND c.run_id = h.run_id
                AND c.native_id = h.cluster_native_id
          LEFT JOIN (
              SELECT hypervisor_instance_id, run_id, host_native_id,
                     COUNT(*) AS num_vms
                FROM vms
               GROUP BY hypervisor_instance_id, run_id, host_native_id
          ) vm_counts
                 ON vm_counts.hypervisor_instance_id = h.hypervisor_instance_id
                AND vm_counts.run_id = h.run_id
                AND vm_counts.host_native_id = h.native_id
         WHERE ((ht.type_key='vmware' AND h.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND h.run_id IN ({hv_ph})))
    """
    params = list(new_vc) + list(new_hv)
    if filter_names:
        ph = ",".join(["%s"] * len(filter_names))
        query += f" AND hi.name IN ({ph})"
        params.extend(filter_names)
    if cluster:
        query += " AND c.name = %s"
        params.append(cluster)
    query += " ORDER BY platform, host_name"
    cur.execute(query, params)
    data = cur.fetchall()
    cur.close(); conn.close()
    return data


@app.route("/api/hosts")
@login_required
def hosts():
    return jsonify(_get_hosts_data(request.args))


@app.route("/api/hosts/export")
@login_required
def export_hosts():
    data = _get_hosts_data(request.args)
    fmt = request.args.get("format", "csv")
    data = export_utils.rows_with_tb_conversion(data, gb_fields=["memory_total_gb", "memory_used_gb"])
    return export_utils.build_export_response(data, fmt=fmt,
                                              base_filename="hosts", sheet_name="Hosts")


@app.route("/api/host/<path:host_name>")
@login_required
def host_details(host_name):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT h.*, hi.name AS vcenter_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM hosts h
          JOIN hypervisor_instances hi ON h.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE h.name = %s
         ORDER BY h.run_id DESC
         LIMIT 50
    """, (host_name,))
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


# ─────────────────────────────────────────────────────────────
#  VMS
# ─────────────────────────────────────────────────────────────
@app.route("/api/vms")
@login_required
def get_vms():
    (run_vc, run_hv, vcenter_list, host, cluster, q, platform,
     power_state, is_template, bulk_terms) = _parse_common_args(request.args)
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(500, int(request.args.get("per_page", 100)))
    return jsonify(get_unified_vms(run_vc, run_hv, vcenter_list, host, cluster, q,
                                    platform, power_state, is_template, bulk_terms,
                                    page, per_page))


@app.route("/api/vms/export")
@login_required
def export_vms_csv():
    (run_vc, run_hv, vcenter_list, host, cluster, q, platform,
     power_state, is_template, bulk_terms) = _parse_common_args(request.args)
    results = get_unified_vms(run_vc, run_hv, vcenter_list, host, cluster, q,
                               platform, power_state, is_template, bulk_terms,
                               page=1, per_page=1000000)
    fmt = request.args.get("format", "csv")
    data = export_utils.rows_with_tb_conversion(
        results["data"], mb_fields=["ram_mb"], gb_fields=["total_disk_gb"])
    columns = ["vm_name", "platform", "vcenter_name", "cpu", "ram_tb", "os",
               "ip_address", "all_ips", "is_template", "power_state",
               "host_name", "cluster_name", "total_disk_tb", "disk_count", "vm_uuid"]
    base = f"vms_vmware{run_vc or 'latest'}_hyperv{run_hv or 'latest'}"
    return export_utils.build_export_response(data, fmt=fmt, base_filename=base,
                                              columns=columns, sheet_name="VMs")


@app.route("/vm/<path:vm_name>")
@login_required
def vm_detail_page(vm_name):
    return render_template("vm_detail.html", vm_name=vm_name,
                           requested_uuid=request.args.get("uuid"),
                           requested_ip=request.args.get("ip"))


@app.route("/api/vm/<path:vm_name>/history")
@login_required
def vm_history(vm_name):
    vm_uuid = request.args.get("uuid")
    filter_ip = request.args.get("ip")

    conn = get_db_connection(); cur = conn.cursor()

    where = ["v.name = %s"]
    params = [vm_name]
    if vm_uuid:
        where.append("v.native_id = %s"); params.append(vm_uuid)
    if filter_ip:
        where.append("(v.primary_ip = %s OR v.all_ips LIKE %s)")
        params.extend([filter_ip, f"%{filter_ip}%"])

    cur.execute(f"""
        SELECT v.id AS vm_id, v.run_id, v.native_id AS vm_uuid,
               v.cpu_count AS cpu, v.memory_mb AS ram_mb,
               v.os_name AS os, v.os_version,
               v.primary_ip AS ip_address, v.all_ips,
               v.hostname, v.nic_count, v.disk_count, v.total_disk_gb,
               v.actual_disk_gb, v.is_template, v.power_state,
               v.tools_version, v.uptime_days,
               v.hypervisor_instance_id,
               cr.legacy_run_id, cr.started_at AS run_timestamp,
               cr.status AS collection_status,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform,
               hi.name AS environment,
               h.name AS host_name,
               c.name AS cluster_name
          FROM vms v
          JOIN collection_runs cr ON v.run_id = cr.id
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN hosts h
                 ON h.hypervisor_instance_id = v.hypervisor_instance_id
                AND h.run_id = v.run_id
                AND h.native_id = v.host_native_id
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = v.hypervisor_instance_id
                AND c.run_id = v.run_id
                AND c.native_id = v.cluster_native_id
         WHERE {' AND '.join(where)}
         ORDER BY cr.started_at DESC
    """, params)
    rows = cur.fetchall()

    if not rows:
        cur.close(); conn.close()
        return jsonify({"vm_name": vm_name, "runs": [], "platform": None})

    ids = tuple({r["vm_id"] for r in rows})
    ph = ",".join(["%s"] * len(ids))
    cur.execute(f"""
        SELECT vm_id, run_id, disk_path, size_gb AS disk_size_gb,
               actual_size_gb, is_shared, shared_vm_count, controller
          FROM vm_disks WHERE vm_id IN ({ph})
    """, ids)
    disks_raw = cur.fetchall()

    cur.execute(f"""
        SELECT vm_id, run_id, partition_path, capacity_gb, used_gb, free_gb,
               usage_percent AS usage_pct
          FROM vm_disk_usage WHERE vm_id IN ({ph})
    """, ids)
    parts_raw = cur.fetchall()

    cur.close(); conn.close()

    disks_by_key = {}
    for d in disks_raw:
        disks_by_key.setdefault((d["vm_id"], d["run_id"]), []).append(d)
    parts_by_key = {}
    for p in parts_raw:
        parts_by_key.setdefault((p["vm_id"], p["run_id"]), []).append(p)

    all_runs = []
    for r in rows:
        row = dict(r)
        row["run_id"] = row["legacy_run_id"]
        row["vm_inventory_id"] = row["vm_id"]
        key = (row["vm_id"], r["run_id"])
        row["disks"] = disks_by_key.get(key, [])
        row["partitions"] = parts_by_key.get(key, [])
        row.setdefault("host_name", None)
        row.setdefault("cluster_name", None)
        row["mac_address"] = None
        row["vmware_tools_status"] = row.get("tools_version")
        row["snapshot_count"] = None
        row["vm_folder"] = None
        row["notes"] = None
        row["state"] = None
        all_runs.append(row)

    from collections import defaultdict
    runs_by_identity = defaultdict(list)
    for r in all_runs:
        identity = (r["platform"], r.get("vm_uuid") or r["vm_id"])
        runs_by_identity[identity].append(r)
    for k in runs_by_identity:
        runs_by_identity[k].sort(key=lambda x: x["run_timestamp"] or "", reverse=True)

    TRACKED = ["cpu", "ram_mb", "total_disk_gb", "disk_count", "ip_address",
               "os", "power_state", "is_template", "nic_count", "hostname"]
    for r in all_runs:
        r["changes"] = {}
        identity = (r["platform"], r.get("vm_uuid") or r["vm_id"])
        vm_runs = runs_by_identity[identity]
        try:
            idx = next(i for i, x in enumerate(vm_runs) if x is r)
        except StopIteration:
            continue
        if idx < len(vm_runs) - 1:
            prev = vm_runs[idx + 1]
            for f in TRACKED:
                a, b = r.get(f), prev.get(f)
                try: a = float(a) if a is not None else None
                except (TypeError, ValueError): pass
                try: b = float(b) if b is not None else None
                except (TypeError, ValueError): pass
                if a != b:
                    r["changes"][f] = {"from": prev.get(f), "to": r.get(f)}

        for k, v in list(r.items()):
            if hasattr(v, "isoformat"): r[k] = v.isoformat()
            elif hasattr(v, "__float__") and not isinstance(v, (int, bool)): r[k] = float(v)
        for d in r["disks"]:
            for k, v in list(d.items()):
                if hasattr(v, "isoformat"): d[k] = v.isoformat()
                elif hasattr(v, "__float__") and not isinstance(v, (int, bool)): d[k] = float(v)
        for p in r["partitions"]:
            for k, v in list(p.items()):
                if hasattr(v, "isoformat"): p[k] = v.isoformat()
                elif hasattr(v, "__float__") and not isinstance(v, (int, bool)): p[k] = float(v)

    return jsonify({"vm_name": vm_name, "runs": all_runs,
                    "platform": all_runs[0]["platform"] if all_runs else None})


# ─────────────────────────────────────────────────────────────
#  DATASTORES
# ─────────────────────────────────────────────────────────────
def _get_datastores_data(args):
    vcenter = args.get("vcenter")
    cluster = args.get("cluster")
    legacy_vc = args.get("run_id_vmware")
    legacy_hv = args.get("run_id_hyperv")
    new_vc, new_hv = _new_run_ids(legacy_vc, legacy_hv)

    conn = get_db_connection(); cur = conn.cursor()
    filter_names = None
    if vcenter and vcenter.strip() and vcenter.lower() != "all":
        filter_names = [v.strip() for v in vcenter.split(",") if v.strip()]

    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    query = f"""
        SELECT d.name AS datastore_name, d.status, d.`accessible` AS is_accessible,
               d.type, d.num_vms,
               COALESCE(ROUND(d.capacity_gb,2),0) AS capacity_gb,
               COALESCE(ROUND(d.used_gb,2),0) AS used_gb,
               COALESCE(ROUND(d.free_gb,2),0) AS free_gb,
               COALESCE(ROUND(d.free_percent,2),0) AS free_percent,
               COALESCE(ROUND(d.provisioned_gb,2),0) AS provisioned_gb,
               c.name AS cluster_name,
               hi.name AS vcenter_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM datastores d
          JOIN hypervisor_instances hi ON d.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = d.hypervisor_instance_id
                AND c.run_id = d.run_id
                AND c.native_id = d.cluster_native_id
         WHERE ((ht.type_key='vmware' AND d.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND d.run_id IN ({hv_ph})))
    """
    params = list(new_vc) + list(new_hv)
    if filter_names:
        ph = ",".join(["%s"] * len(filter_names))
        query += f" AND hi.name IN ({ph})"
        params.extend(filter_names)
    if cluster:
        query += " AND c.name = %s"
        params.append(cluster)
    query += " ORDER BY platform, datastore_name"
    cur.execute(query, params)
    data = cur.fetchall()
    cur.close(); conn.close()
    return data


@app.route("/api/datastores")
@login_required
def datastores():
    return jsonify(_get_datastores_data(request.args))


@app.route("/api/datastores/export")
@login_required
def export_datastores():
    data = _get_datastores_data(request.args)
    fmt = request.args.get("format", "csv")
    data = export_utils.rows_with_tb_conversion(
        data, gb_fields=["capacity_gb", "used_gb", "free_gb", "provisioned_gb"])
    return export_utils.build_export_response(data, fmt=fmt,
                                              base_filename="datastores",
                                              sheet_name="Datastores")


@app.route("/api/datastore_vms")
@login_required
def datastore_vms():
    datastore = request.args.get("datastore")
    cluster = request.args.get("cluster")
    legacy_vc = request.args.get("run_id_vmware")
    legacy_hv = request.args.get("run_id_hyperv")
    new_vc, new_hv = _new_run_ids(legacy_vc, legacy_hv)

    if not datastore:
        return jsonify([])
    datastore_clean = datastore.strip()

    conn = get_db_connection(); cur = conn.cursor()
    results = []

    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    vc_query = f"""
        SELECT DISTINCT v.name AS vm_name, v.cpu_count AS cpu, v.memory_mb AS ram_mb,
               v.os_name AS os, v.primary_ip AS ip_address, v.total_disk_gb,
               hi.name AS vcenter_name, 'VMware' AS platform
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          JOIN vm_disks d ON d.vm_id = v.id AND d.run_id = v.run_id
          JOIN datastores ds ON ds.hypervisor_instance_id = v.hypervisor_instance_id
                AND ds.run_id = v.run_id AND ds.name = %s
         WHERE v.run_id IN ({vc_ph}) AND ht.type_key='vmware'
           AND TRIM(SUBSTRING_INDEX(SUBSTRING_INDEX(d.disk_path,']',1),'[',-1)) = ds.name
    """
    params = [datastore_clean] + list(new_vc)
    if cluster:
        vc_query += " AND ds.cluster_native_id = (SELECT c2.native_id FROM clusters c2 WHERE c2.hypervisor_instance_id=ds.hypervisor_instance_id AND c2.run_id=ds.run_id AND c2.name=%s LIMIT 1)"
        params.append(cluster)
    cur.execute(vc_query, params)
    results.extend(cur.fetchall())

    hv_query = f"""
        SELECT DISTINCT v.name AS vm_name, v.cpu_count AS cpu, v.memory_mb AS ram_mb,
               v.os_name AS os, v.primary_ip AS ip_address, v.total_disk_gb,
               hi.name AS vcenter_name, 'Hyper-V' AS platform
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          JOIN vm_disks d ON d.vm_id = v.id AND d.run_id = v.run_id
          JOIN datastores ds ON ds.hypervisor_instance_id = v.hypervisor_instance_id
                AND ds.run_id = v.run_id AND ds.name = %s
         WHERE v.run_id IN ({hv_ph}) AND ht.type_key='hyperv'
    """
    cur.execute(hv_query, [datastore_clean] + list(new_hv))
    results.extend(cur.fetchall())

    cur.close(); conn.close()
    return jsonify(results)


# ─────────────────────────────────────────────────────────────
#  SEARCH
# ─────────────────────────────────────────────────────────────
@app.route("/api/search")
@login_required
def search():
    q = request.args.get("q", "")
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT v.name AS vm_name, v.primary_ip AS ip_address FROM vms v
         WHERE v.name LIKE %s OR v.primary_ip LIKE %s
         ORDER BY v.name LIMIT 50
    """, (f"%{q}%", f"%{q}%"))
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


# ─────────────────────────────────────────────────────────────
#  RUN SCRIPT
# ─────────────────────────────────────────────────────────────
@app.route("/api/run_script", methods=["POST"])
@login_required
@superadmin_required
def run_script():
    try:
        result = subprocess.run(
            ["ssh", "root@localhost", "python3 /root/scripts/get_inventory.py"],
            capture_output=True, text=True, timeout=1800)
        return jsonify({"status": "success", "stdout": result.stdout,
                        "stderr": result.stderr, "returncode": result.returncode})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ─────────────────────────────────────────────────────────────
#  VM BUILDER
# ─────────────────────────────────────────────────────────────
def _latest_new_run(cursor, hypervisor_instance_id):
    for table in ("clusters", "hosts", "datastores", "vms"):
        cursor.execute(f"SELECT MAX(run_id) AS r FROM `{table}` "
                       f"WHERE hypervisor_instance_id=%s", (hypervisor_instance_id,))
        row = cursor.fetchone()
        if row and row["r"] is not None:
            return row["r"]
    return None


@app.route("/api/vcenter_options")
@login_required
def vcenter_options():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT hi.id AS vcenter_id, hi.name AS vcenter_name,
               hi.host AS hostname,
               json_unquote(json_extract(hi.connection_options,'$.ip_address')) AS ip_address
          FROM hypervisor_instances hi
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE hi.deleted_at IS NULL AND hi.enabled = 1 AND ht.enabled = 1
           AND ht.type_key='vmware'
         ORDER BY hi.name
    """)
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


@app.route("/api/infra_options/clusters")
@login_required
def infra_clusters():
    vc_id = request.args.get("vcenter_id")
    conn = get_db_connection(); cur = conn.cursor()
    run_id = _latest_new_run(cur, vc_id)
    if not run_id:
        cur.close(); conn.close(); return jsonify([])
    cur.execute("""
        SELECT c.name AS cluster_name, c.num_hosts, c.num_vms,
               ROUND(c.cpu_free_mhz/1000,1) AS free_cpu_ghz,
               ROUND(c.memory_free_mb/1024,1) AS free_ram_gb,
               c.cpu_usage_percent, c.memory_usage_percent
          FROM clusters c
         WHERE c.run_id=%s AND c.hypervisor_instance_id=%s
         ORDER BY c.name
    """, (run_id, vc_id))
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


@app.route("/api/infra_options/datastores")
@login_required
def infra_datastores():
    vc_id = request.args.get("vcenter_id")
    conn = get_db_connection(); cur = conn.cursor()
    run_id = _latest_new_run(cur, vc_id)
    if not run_id:
        cur.close(); conn.close(); return jsonify([])
    cur.execute("""
        SELECT d.name AS datastore_name, c.name AS cluster_name, d.type,
               ROUND(d.capacity_gb,1) AS capacity_gb,
               ROUND(d.free_gb,1) AS free_gb,
               ROUND(d.used_gb,1) AS used_gb,
               d.free_percent, d.status
          FROM datastores d
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = d.hypervisor_instance_id
                AND c.run_id = d.run_id
                AND c.native_id = d.cluster_native_id
         WHERE d.run_id=%s AND d.hypervisor_instance_id=%s AND d.`accessible`=1
         ORDER BY d.free_gb DESC
    """, (run_id, vc_id))
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


@app.route("/api/infra_options/hosts")
@login_required
def infra_hosts():
    vc_id = request.args.get("vcenter_id")
    cluster_name = request.args.get("cluster")
    conn = get_db_connection(); cur = conn.cursor()
    run_id = _latest_new_run(cur, vc_id)
    if not run_id:
        cur.close(); conn.close(); return jsonify([])
    query = """
        SELECT h.name AS host_name, c.name AS cluster_name, h.cpu_cores,
               ROUND(h.memory_total_mb/1024,1) AS memory_total_gb,
               ROUND(h.memory_used_mb/1024,1)  AS memory_used_gb,
               ROUND((h.memory_total_mb-h.memory_used_mb)/1024,1) AS memory_free_gb,
               h.power_state, h.connection_state
          FROM hosts h
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = h.hypervisor_instance_id
                AND c.run_id = h.run_id
                AND c.native_id = h.cluster_native_id
         WHERE h.run_id=%s AND h.hypervisor_instance_id=%s
           AND h.connection_state='connected' AND h.power_state='poweredOn'
    """
    params = [run_id, vc_id]
    if cluster_name:
        query += " AND c.name = %s"
        params.append(cluster_name)
    query += " ORDER BY h.name"
    cur.execute(query, params)
    data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


@app.route("/api/infra_options/templates")
@login_required
def infra_templates():
    vc_id = request.args.get("vcenter_id")
    conn = get_db_connection(); cur = conn.cursor()
    run_id = _latest_new_run(cur, vc_id)
    if not run_id:
        cur.close(); conn.close(); return jsonify([])

    cur.execute("""
        SELECT v.name AS template_name, v.os_name AS os,
               v.cpu_count AS default_cpu, v.memory_mb AS default_ram
          FROM vms v
         WHERE v.run_id=%s AND v.hypervisor_instance_id=%s AND v.is_template=1
         ORDER BY v.name
    """, (run_id, vc_id))
    data = cur.fetchall()

    if not data:
        cur.execute("""
            SELECT v.name AS template_name, v.os_name AS os,
                   v.cpu_count AS default_cpu, v.memory_mb AS default_ram
              FROM vms v
             WHERE v.run_id=%s AND v.hypervisor_instance_id=%s
               AND (LOWER(v.name) LIKE %s OR LOWER(v.name) LIKE %s
                    OR LOWER(v.name) LIKE %s OR LOWER(v.name) LIKE %s
                    OR LOWER(v.name) LIKE %s)
             ORDER BY v.name
        """, (run_id, vc_id, "%temp%", "%tmpl%", "%golden%", "%base%", "%master%"))
        data = cur.fetchall()
    if not data:
        cur.execute("""
            SELECT v.name AS template_name, v.os_name AS os,
                   v.cpu_count AS default_cpu, v.memory_mb AS default_ram
              FROM vms v
             WHERE v.run_id=%s AND v.hypervisor_instance_id=%s
             ORDER BY v.name LIMIT 200
        """, (run_id, vc_id))
        data = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(data)


@app.route("/api/infra_options/networks")
@login_required
def infra_networks():
    return jsonify([])


# ─────────────────────────────────────────────────────────────
#  VM PROVISION
# ─────────────────────────────────────────────────────────────
def _run_popen(cmd, log_list):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(proc.stdout.readline, ""):
        log_list[0] += line
    proc.wait()
    return proc.returncode


def _write_extra_vars_file(vars_dict):
    os.makedirs(config.ANSIBLE_TMP_DIR, exist_ok=True)
    path = os.path.join(config.ANSIBLE_TMP_DIR, f"vars_{uuid.uuid4().hex}.json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(vars_dict, f)
    return path


def run_vm_jobs(job_id, vms):
    job = vm_jobs[job_id]
    job["status"] = "running"
    for idx, vm in enumerate(vms):
        job["vms"][idx]["status"] = "running"
        log = [""]
        hypervisor = vm.get("hypervisor_type", "vmware").lower().strip()
        vm_os = vm.get("vm_os_type", "linux").lower().strip()
        job["vms"][idx]["log"] = f"[VMBuilDeR] Hypervisor: {hypervisor.upper()} | OS: {vm_os.upper()}\n\n"
        if hypervisor == "hyperv":
            playbook = PLAYBOOK_CREATE_VM_HYPERV
            extra_vars = {
                "hyperv_host": vm["vcenter_hostname"],
                "hyperv_user": vm["vcenter_username"],
                "hyperv_password": vm["vcenter_password"],
                "vm_name": vm["vm_name"],
                "vm_hostname": vm["vm_hostname"],
                "datastore_name": vm.get("datastore_name") or "C:\\ClusterStorage\\Volume1",
                "vm_folder": vm.get("vm_folder") or "",
                "template_name": vm["template_name"],
                "switch_name": vm["network_name"],
                "cpu": vm["cpu"], "ram_mb": vm["ram"],
                "vm_os_type": vm.get("vm_os_type") or "linux",
                "vm_ip": vm["vm_ip"], "vm_netmask": vm["vm_netmask"],
                "vm_gateway": vm["vm_gateway"], "vm_dns": vm["vm_dns"],
                "vm_admin_password": vm.get("vm_admin_password") or "",
                "win_iso_path": vm.get("win_iso_path") or "",
            }
        else:
            playbook = PLAYBOOK_CREATE_VM_VMWARE
            extra_vars = {
                "vcenter_hostname": vm["vcenter_hostname"],
                "vcenter_username": vm["vcenter_username"],
                "vcenter_password": vm["vcenter_password"],
                "datacenter_name": vm["datacenter_name"],
                "cluster_name": vm["cluster_name"],
                "template_name": vm["template_name"],
                "vm_name": vm["vm_name"], "vm_hostname": vm["vm_hostname"],
                "vm_ip": vm["vm_ip"], "vm_netmask": vm["vm_netmask"],
                "vm_gateway": vm["vm_gateway"], "vm_dns": vm["vm_dns"],
                "datastore_name": vm["datastore_name"],
                "vm_folder": vm.get("vm_folder", ""),
                "cpu": vm["cpu"], "ram": vm["ram"],
                "disk_size": vm["disk_size"], "disk_type": vm["disk_type"],
                "network_name": vm["network_name"],
            }
        vars_path = _write_extra_vars_file(extra_vars)
        try:
            rc = _run_popen(["ansible-playbook", playbook, "-e", f"@{vars_path}"], log)
        finally:
            try: os.remove(vars_path)
            except OSError: pass
        job["vms"][idx]["log"] += log[0]
        if rc != 0:
            job["vms"][idx]["status"] = "failed"
            continue
        user_data = vm.get("user_data", "").strip()
        if not user_data:
            job["vms"][idx]["status"] = "success"; continue
        job["vms"][idx]["log"] += "\n─── Post-Install Script ───────\n"
        log2 = [""]
        if vm_os == "windows":
            ad_hoc_vars = {
                "ansible_user": vm.get("vm_admin_user", "Administrator"),
                "ansible_password": vm.get("vm_admin_password", ""),
                "ansible_connection": "winrm",
                "ansible_winrm_transport": "ntlm",
                "ansible_winrm_server_cert_validation": "ignore",
            }
            vars_path2 = _write_extra_vars_file(ad_hoc_vars)
            ps_cmd = ["ansible", vm["vm_ip"], "-m", "win_shell",
                      "-a", user_data, "-e", f"@{vars_path2}"]
        else:
            vars_path2 = None
            ps_cmd = ["ansible", vm["vm_ip"], "-u", "root", "-m", "shell", "-a", user_data,
                      "--ssh-extra-args", "-o StrictHostKeyChecking=no -o ConnectTimeout=30"]
        try:
            rc2 = _run_popen(ps_cmd, log2)
        finally:
            if vars_path2:
                try: os.remove(vars_path2)
                except OSError: pass
        job["vms"][idx]["log"] += log2[0]
        job["vms"][idx]["status"] = "success" if rc2 == 0 else "failed"
    job["status"] = ("done" if all(v["status"] == "success" for v in job["vms"])
                     else "done_with_errors")


@app.route("/api/create_vm", methods=["POST"])
@login_required
def api_create_vm():
    vms = []
    csv_file = request.files.get("csv_file")
    if csv_file and csv_file.filename:
        stream = io.StringIO(csv_file.stream.read().decode("utf-8"))
        for row in csv.DictReader(stream):
            vms.append(row)
    else:
        fields = ["hypervisor_type", "vm_os_type", "vcenter_hostname", "vcenter_username",
                  "vcenter_password", "datacenter_name", "cluster_name", "template_name",
                  "vm_name", "vm_hostname", "vm_folder", "vm_ip", "vm_netmask",
                  "vm_gateway", "vm_dns", "datastore_name", "network_name",
                  "cpu", "ram", "disk_size", "disk_type", "user_data",
                  "vm_admin_user", "vm_admin_password", "linux_repo_url",
                  "win_iso_path", "win_share_path", "win_share_user", "win_share_password"]
        lists = {f: request.form.getlist(f) for f in fields}
        for i in range(len(lists["vm_name"])):
            vms.append({f: lists[f][i] if i < len(lists[f]) else "" for f in fields})
    job_id = str(uuid.uuid4())
    vm_jobs[job_id] = {
        "status": "pending", "submitted_by": session.get("username"),
        "vms": [{"name": vm.get("vm_name", f"VM-{i+1}"), "status": "pending", "log": ""}
                for i, vm in enumerate(vms)],
    }
    threading.Thread(target=run_vm_jobs, args=(job_id, vms), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/vm_job_status/<job_id>")
@login_required
def vm_job_status(job_id):
    def generate():
        while True:
            job = vm_jobs.get(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                break
            yield f"data: {json.dumps(job)}\n\n"
            if job["status"] in ("done", "done_with_errors"):
                break
            time.sleep(1.5)
    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# ─────────────────────────────────────────────────────────────
#  AI / ML
# ─────────────────────────────────────────────────────────────
def train_cpu_forecast_model(cluster_name, historical_data):
    if len(historical_data) < 4: return None
    df = pd.DataFrame(historical_data).sort_values("run_timestamp")
    usages = df["cpu_usage_percent"].values
    X, y = [], []
    for i in range(3, len(usages)):
        X.append([usages[i-3], usages[i-2], usages[i-1]])
        y.append(usages[i])
    model = LinearRegression().fit(np.array(X), np.array(y))
    joblib.dump(model, os.path.join(MODEL_DIR, f"{cluster_name}_cpu_model.pkl"))
    return model


def predict_next_cpu_usage(cluster_name, last_three):
    path = os.path.join(MODEL_DIR, f"{cluster_name}_cpu_model.pkl")
    if not os.path.exists(path): return None
    model = joblib.load(path)
    return model.predict(np.array([last_three]).reshape(1, -1))[0]


def get_vm_placement_suggestions(vm_requirements, run_id_vmware=None, run_id_hyperv=None):
    new_vc, new_hv = _new_run_ids(run_id_vmware, run_id_hyperv)
    conn = get_db_connection(); cur = conn.cursor()

    req_cpu_cores = vm_requirements.get("cpu_cores", 2)
    req_ram_gb = vm_requirements.get("ram_gb", 4)
    req_storage_gb = vm_requirements.get("storage_gb", 50)

    cur.execute("SELECT AVG(cpu_mhz) AS avg_mhz FROM hosts WHERE run_id IN (%s)"
                % ",".join(["%s"] * len(new_vc)), tuple(new_vc))
    row = cur.fetchone()
    avg_cpu_mhz = row["avg_mhz"] if row and row["avg_mhz"] else 2500
    req_cpu_mhz = req_cpu_cores * avg_cpu_mhz
    req_ram_mb = req_ram_gb * 1024

    suggestions = []

    def collect(platform_label, new_run_ids, type_key):
        ph = ",".join(["%s"] * len(new_run_ids))
        cur.execute(f"""
            SELECT c.name AS cluster_name, hi.name AS vcenter_name,
                   c.num_hosts, c.num_vms, c.cpu_free_mhz, c.memory_free_mb,
                   c.storage_free_gb, c.cpu_usage_percent, c.memory_usage_percent,
                   c.storage_usage_percent, c.cpu_total_mhz, c.memory_total_mb,
                   c.storage_total_gb
              FROM clusters c
              JOIN hypervisor_instances hi ON c.hypervisor_instance_id=hi.id
              JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
             WHERE ht.type_key=%s AND c.run_id IN ({ph})
               AND c.cpu_free_mhz   >= %s
               AND c.memory_free_mb >= %s
               AND c.storage_free_gb>= %s
        """, [type_key] + list(new_run_ids) + [req_cpu_mhz, req_ram_mb, req_storage_gb])
        for row in cur.fetchall():
            cpu_ratio = (row["cpu_free_mhz"] - req_cpu_mhz) / (row["cpu_total_mhz"] or 1)
            mem_ratio = (row["memory_free_mb"] - req_ram_mb) / (row["memory_total_mb"] or 1)
            sto_ratio = (row["storage_free_gb"] - req_storage_gb) / (row["storage_total_gb"] or 1)
            cpu_score = min(100, max(0, cpu_ratio * 100))
            mem_score = min(100, max(0, mem_ratio * 100))
            sto_score = min(100, max(0, sto_ratio * 100))
            penalty = 1.0
            for pct in (row["cpu_usage_percent"], row["memory_usage_percent"], row["storage_usage_percent"]):
                if pct and pct > 70: penalty *= 0.7
            total = (cpu_score*0.4 + mem_score*0.35 + sto_score*0.25) * penalty
            suggestions.append({
                "platform": platform_label,
                "cluster_name": row["cluster_name"],
                "vcenter_name": row.get("vcenter_name"),
                "resource_name": (f"{row['cluster_name']} ({row['vcenter_name']})"
                                   if row.get("vcenter_name") else row["cluster_name"]),
                "total_score": round(total, 2),
                "scores": {"cpu": round(cpu_score,2), "ram": round(mem_score,2), "storage": round(sto_score,2)},
                "available_resources": {
                    "free_cpu_mhz": row["cpu_free_mhz"],
                    "free_ram_gb": round((row["memory_free_mb"] or 0)/1024, 2),
                    "free_storage_gb": round(row["storage_free_gb"] or 0, 2),
                    "current_cpu_usage": round(row["cpu_usage_percent"] or 0, 2),
                    "current_memory_usage": round(row["memory_usage_percent"] or 0, 2),
                    "current_storage_usage": round(row["storage_usage_percent"] or 0, 2),
                },
                "num_hosts": row["num_hosts"], "num_vms": row["num_vms"],
            })

    if vm_requirements.get("platform") in ("any", "vmware") and new_vc:
        collect("VMware", new_vc, "vmware")
    if vm_requirements.get("platform") in ("any", "hyperv") and new_hv:
        collect("Hyper-V", new_hv, "hyperv")

    cur.close(); conn.close()
    suggestions.sort(key=lambda x: x["total_score"], reverse=True)
    return suggestions


@app.route("/api/vm/suggestions", methods=["POST"])
@login_required
def vm_placement_suggestions():
    try:
        data = request.json
        reqs = {"cpu_cores": int(data.get("cpu_cores", 2)),
                "ram_gb": int(data.get("ram_gb", 4)),
                "storage_gb": int(data.get("storage_gb", 50)),
                "platform": data.get("platform", "any")}
        suggestions = get_vm_placement_suggestions(reqs, data.get("run_id_vmware"), data.get("run_id_hyperv"))
        return jsonify({"success": True, "requirements": reqs,
                        "suggestions": suggestions[:10],
                        "total_candidates": len(suggestions)})
    except Exception:
        logger.exception("vm_placement_suggestions failed")
        return jsonify({"success": False, "error": "Could not compute placement suggestions."}), 400


@app.route("/api/vm/suggestions/from_vm/<path:vm_name>")
@login_required
def get_suggestions_from_vm(vm_name):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT v.cpu_count AS cpu, v.memory_mb AS ram_mb, v.total_disk_gb,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE v.name=%s
         ORDER BY v.run_id DESC LIMIT 1
    """, (vm_name,))
    vm = cur.fetchone()
    cur.close(); conn.close()
    if not vm:
        return jsonify({"success": False, "error": "VM not found"}), 404
    reqs = {"cpu_cores": vm["cpu"] or 2,
            "ram_gb": int((vm["ram_mb"] or 4096)/1024),
            "storage_gb": int(vm["total_disk_gb"] or 50),
            "platform": "any"}
    return jsonify({"success": True, "source_vm": vm_name,
                    "source_platform": vm["platform"],
                    "requirements": reqs,
                    "suggestions": get_vm_placement_suggestions(reqs)[:10]})


@app.route("/api/ai/train_models")
@login_required
@superadmin_required
def train_models():
    conn = get_db_connection(); cur = conn.cursor()
    results = []
    cur.execute("SELECT DISTINCT name FROM clusters")
    for row in cur.fetchall():
        cn = row["name"]
        cur.execute("""
            SELECT cr.started_at AS run_timestamp, c.cpu_usage_percent
              FROM clusters c JOIN collection_runs cr ON c.run_id=cr.id
             WHERE c.name=%s ORDER BY cr.started_at ASC LIMIT 30
        """, (cn,))
        hist = cur.fetchall()
        if len(hist) >= 4:
            train_cpu_forecast_model(cn, hist)
            results.append({"cluster": cn, "status": "trained"})
        else:
            results.append({"cluster": cn, "status": "insufficient data"})
    cur.close(); conn.close()
    return jsonify({"results": results})


@app.route("/api/ai/predict_cpu/<path:cluster_name>")
@login_required
def predict_cpu(cluster_name):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT c.cpu_usage_percent
          FROM clusters c JOIN collection_runs cr ON c.run_id=cr.id
         WHERE c.name=%s ORDER BY cr.started_at DESC LIMIT 3
    """, (cluster_name,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    if len(rows) != 3:
        return jsonify({"error": "Not enough historical data"}), 400
    last_three = [r["cpu_usage_percent"] for r in rows]
    prediction = predict_next_cpu_usage(cluster_name, last_three)
    if prediction is None:
        return jsonify({"error": "Model not trained yet"}), 404
    return jsonify({"cluster": cluster_name, "last_three": last_three,
                    "predicted_next_cpu": round(float(prediction), 2), "unit": "%"})


# ─────────────────────────────────────────────────────────────
#  SITE ENDPOINTS (backward compatibility)
# ─────────────────────────────────────────────────────────────
def get_aggregated_site_data(run_id, site_name, vcenter_list):
    conn = get_db_connection(); cur = conn.cursor()
    if not run_id:
        cur.execute("SELECT MAX(legacy_run_id) AS max_run FROM collection_runs")
        run_id = cur.fetchone()["max_run"]
    ph = ",".join(["%s"] * len(vcenter_list))
    cur.execute(f"""
        SELECT SUM(num_vms) AS total_vms, SUM(total_cores) AS total_cores,
               SUM(used_cpu_mhz) AS used_cpu_mhz, SUM(free_cpu_mhz) AS free_cpu_mhz,
               SUM(total_cpu_vms) AS total_cpu_vms,
               SUM(total_memory_gb) AS total_memory_gb,
               SUM(used_memory_gb) AS used_memory_gb,
               SUM(free_memory_gb) AS free_memory_gb,
               SUM(total_memory_vms_gb) AS total_memory_vms_gb,
               SUM(total_storage_gb) AS total_storage_gb,
               SUM(used_storage_gb) AS used_storage_gb,
               SUM(free_storage_gb) AS free_storage_gb,
               SUM(num_clusters) AS total_clusters, SUM(num_hosts) AS total_hosts,
               SUM(num_datastores) AS total_datastores,
               AVG(cpu_usage_percent) AS avg_cpu_usage_percent,
               AVG(memory_usage_percent) AS avg_memory_usage_percent,
               AVG(storage_usage_percent) AS avg_storage_usage_percent,
               GROUP_CONCAT(DISTINCT Vcenter) AS vcenter_list
          FROM vcenter_summary_all_runs
         WHERE run_id=%s AND Vcenter IN ({ph})
    """, (run_id, *vcenter_list))
    agg = cur.fetchone()
    cur.execute("SELECT legacy_run_id AS run_id, MIN(started_at) AS run_timestamp "
                "FROM collection_runs GROUP BY legacy_run_id ORDER BY legacy_run_id DESC")
    runs = cur.fetchall()
    cur.close(); conn.close()
    data = []
    if agg and agg["total_vms"] is not None:
        avg_cpu = agg["avg_cpu_usage_percent"] or 0
        avg_mem = agg["avg_memory_usage_percent"] or 0
        avg_sto = agg["avg_storage_usage_percent"] or 0
        total_cpu_vms = agg["total_cpu_vms"] or 0
        total_cores = agg["total_cores"] or 1
        total_mem_gb = agg["total_memory_gb"] or 1
        cpu_ratio = round(total_cpu_vms/total_cores, 2) if total_cores > 0 else 0
        mem_ratio = round((agg["total_memory_vms_gb"] or 0)/total_mem_gb, 2) if total_mem_gb > 0 else 0
        data.append({
            "Vcenter": f"{site_name}_Site_Aggregated", "ip_vcenter": "",
            "num_clusters": agg["total_clusters"] or 0,
            "num_hosts": agg["total_hosts"] or 0,
            "num_datastores": agg["total_datastores"] or 0,
            "num_vms": agg["total_vms"] or 0,
            "total_cores": agg["total_cores"] or 0,
            "cpu_usage_percent": round(avg_cpu,2),
            "used_cores": agg["used_cpu_mhz"] or 0,
            "free_cores": agg["free_cpu_mhz"] or 0,
            "total_memory_gb": agg["total_memory_gb"] or 0,
            "memory_usage_percent": round(avg_mem,2),
            "used_memory_gb": agg["used_memory_gb"] or 0,
            "free_memory_gb": agg["free_memory_gb"] or 0,
            "total_storage_gb": agg["total_storage_gb"] or 0,
            "storage_usage_percent": round(avg_sto,2),
            "used_storage_gb": agg["used_storage_gb"] or 0,
            "free_storage_gb": agg["free_storage_gb"] or 0,
            "Subscription_cpu_ratio": cpu_ratio,
            "total_cpu_vms": agg["total_cpu_vms"] or 0,
            "Subscription_memory_ratio": mem_ratio,
            "total_memory_vms_gb": agg["total_memory_vms_gb"] or 0,
            "Subscription_storage_ratio": 0, "total_disk_size_gb": 0,
            "vcenter_list": agg["vcenter_list"] or "",
        })
    return jsonify({"run_id": run_id, "data": data, "runs": runs})


@app.route("/api/site/b7")
@login_required
def site_b7():
    return get_aggregated_site_data(request.args.get("run_id"), "B7",
                                    ["HX-VC","CCB7","UCSXD2-VC","UCSXD1-VC"])


@app.route("/api/site/dr")
@login_required
def site_dr():
    return get_aggregated_site_data(request.args.get("run_id"), "DR",
                                    ["MXDR","CCDR","UCSXDR-VC"])


@app.route("/api/site/b90")
@login_required
def site_b90():
    return get_aggregated_site_data(request.args.get("run_id"), "B90", ["TED"])


@app.route("/api/site/testdev")
@login_required
def site_testdev():
    return get_aggregated_site_data(request.args.get("run_id"), "TestDev", ["HPSM","HUAWEI"])


@app.route("/api/dashboard")
@login_required
def dashboard():
    run_id = request.args.get("run_id")
    conn = get_db_connection(); cur = conn.cursor()
    if not run_id:
        cur.execute("SELECT MAX(legacy_run_id) AS max_run FROM collection_runs")
        run_id = cur.fetchone()["max_run"]
    cur.execute("SELECT * FROM vcenter_summary_all_runs WHERE run_id=%s", (run_id,))
    data = cur.fetchall()
    cur.execute("SELECT legacy_run_id AS run_id, MIN(started_at) AS run_timestamp "
                "FROM collection_runs GROUP BY legacy_run_id ORDER BY legacy_run_id DESC")
    runs = cur.fetchall()
    cur.close(); conn.close()
    return jsonify({"run_id": run_id, "data": data, "runs": runs})


# ─────────────────────────────────────────────────────────────
#  DEBUG
# ─────────────────────────────────────────────────────────────
@app.route("/api/debug/hyperv_data")
@login_required
@superadmin_required
def debug_hyperv_data():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT cr.id, cr.legacy_run_id, cr.started_at, cr.status
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE ht.type_key='hyperv' ORDER BY cr.id DESC
    """)
    results = {"hyperv_runs": cur.fetchall()}
    cur.close(); conn.close()
    return jsonify(results)


@app.route("/api/debug/schema")
@login_required
@superadmin_required
def debug_schema():
    table = request.args.get("table", "vms")
    conn = get_db_connection(); cur = conn.cursor()
    try:
        cur.execute(f"DESCRIBE `{table}`")
        cols = cur.fetchall()
    except Exception as e:
        cur.close(); conn.close()
        return jsonify({"error": str(e)})
    cur.close(); conn.close()
    return jsonify({"table": table, "columns": cols})


@app.route("/api/debug/sample")
@login_required
@superadmin_required
def debug_sample():
    table = request.args.get("table", "vms")
    run_id = request.args.get("run_id")
    limit = int(request.args.get("limit", 3))
    conn = get_db_connection(); cur = conn.cursor()
    try:
        if run_id:
            cur.execute(f"SELECT * FROM `{table}` WHERE run_id=%s LIMIT %s", (run_id, limit))
        else:
            cur.execute(f"SELECT * FROM `{table}` LIMIT %s", (limit,))
        rows = cur.fetchall()
    except Exception as e:
        cur.close(); conn.close()
        return jsonify({"error": str(e)})
    cur.close(); conn.close()
    return jsonify(rows)


# ─────────────────────────────────────────────────────────────
#  AI CHAT
# ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
#  AI CHAT — Infra Assistant
# ─────────────────────────────────────────────────────────────
AGENT_NAME = "Infra Assistant"
AGENT_DESC = ("I am Infra Assistant — an AI built for VMware and Hyper-V "
              "infrastructure. I answer questions about clusters, VMs, hosts, "
              "datastores, resource usage, trends, historical reports, capacity "
              "planning, and VM placement suggestions.")


# ── numeric helpers ────────────────────────────────────────────
def _f(val, div=1, dec=1):
    try:
        return round(float(val) / float(div), dec) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _favg(lst, key):
    vals = [float(x[key]) for x in lst if x.get(key) is not None]
    return round(sum(vals) / len(vals), 1) if vals else 0.0


def _kw(text, *kws):
    return any(k in text for k in kws)


def _mk_cluster(row, platform, vcenter=None):
    return {
        "name": row["cluster_name"], "platform": platform,
        "vcenter": vcenter or row.get("vcenter_name") or row["cluster_name"],
        "free_cpu_ghz": _f(row.get("free_cpu_mhz"), 1000),
        "free_ram_gb": _f(row.get("free_memory_mb"), 1024),
        "free_storage_tb": _f(row.get("free_storage_gb"), 1024),
        "total_cpu_ghz": _f(row.get("total_cpu_mhz"), 1000),
        "total_ram_gb": _f(row.get("total_memory_mb"), 1024),
        "total_storage_gb": _f(row.get("total_storage_gb")),
        "cpu_usage": _f(row.get("cpu_usage_percent")),
        "mem_usage": _f(row.get("memory_usage_percent")),
        "storage_usage": _f(row.get("storage_usage_percent")),
        "num_vms": int(row.get("num_vms") or 0),
        "num_hosts": int(row.get("num_hosts") or 0),
    }


def _mk_ds(row, platform):
    fp = _f(row.get("free_percent"))
    return {
        "name": row["datastore_name"], "cluster": row.get("cluster_name"),
        "platform": platform, "free_gb": _f(row.get("free_gb")),
        "used_gb": _f(row.get("used_gb")), "capacity_gb": _f(row.get("capacity_gb")),
        "free_percent": fp, "used_percent": round(100.0 - fp, 1),
    }


# ── Ollama caller — tries several models, never raises ─────────
def _llm(prompt, model="phi3-local:latest"):
    import requests as _rq
    for m in (model, "phi3:latest", "phi3-mini:latest", "tinyllama:latest"):
        try:
            r = _rq.post(
                getattr(config, "OLLAMA_URL", "http://localhost:11434/api/generate"),
                json={"model": m, "prompt": prompt, "stream": False,
                      "options": {"temperature": 0.1, "num_ctx": 4096,
                                  "num_predict": 400}},
                timeout=120)
            if r.status_code == 200:
                raw = r.json().get("response", "").strip()
                for mk in ("### Answer", "Answer:", "### Question", "Question:"):
                    if mk in raw:
                        raw = raw.split(mk)[-1].strip()
                if raw:
                    return raw
        except Exception:
            continue
    return None


# ── dataset loader — ONE place that fetches everything ai_ask needs ──
def _ai_load_dataset():
    """
    Return a dict with all data the AI layer needs. Reads only unified
    vcenter_inventory_v3 tables. Caller is responsible for closing
    the returned connection — or just let the request end.
    """
    conn = get_db_connection(); cur = conn.cursor()
    new_vc, new_hv = _new_run_ids(None, None)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    cur.execute(f"""
        SELECT c.name AS cluster_name, hi.name AS vcenter_name,
               c.cpu_free_mhz AS free_cpu_mhz,
               c.memory_free_mb AS free_memory_mb,
               c.storage_free_gb AS free_storage_gb,
               c.cpu_usage_percent, c.memory_usage_percent, c.storage_usage_percent,
               c.cpu_total_mhz AS total_cpu_mhz,
               c.memory_total_mb AS total_memory_mb,
               c.storage_total_gb, c.num_vms, c.num_hosts,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ((ht.type_key='vmware' AND c.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND c.run_id IN ({hv_ph})))
    """, list(new_vc) + list(new_hv))
    raw_clusters = cur.fetchall()

    cur.execute(f"""
        SELECT d.name AS datastore_name,
               c.name AS cluster_name,
               d.free_gb, d.used_gb, d.capacity_gb, d.free_percent,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM datastores d
          JOIN hypervisor_instances hi ON d.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
          LEFT JOIN clusters c
                 ON c.hypervisor_instance_id = d.hypervisor_instance_id
                AND c.run_id = d.run_id
                AND c.native_id = d.cluster_native_id
         WHERE ((ht.type_key='vmware' AND d.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND d.run_id IN ({hv_ph})))
         ORDER BY d.free_percent ASC
         LIMIT 60
    """, list(new_vc) + list(new_hv))
    raw_ds = cur.fetchall()

    cur.execute(f"""
        SELECT h.name AS host_name, hi.name AS vcenter_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform,
               h.cpu_cores, h.cpu_threads, h.cpu_mhz,
               h.memory_total_mb / 1024 AS memory_total_gb,
               h.memory_used_mb  / 1024 AS memory_used_gb,
               h.power_state, h.connection_state,
               h.model, h.vendor, h.os_version,
               (SELECT COUNT(*) FROM vms v
                 WHERE v.host_native_id = h.native_id
                   AND v.hypervisor_instance_id = h.hypervisor_instance_id
                   AND v.run_id = h.run_id) AS num_vms
          FROM hosts h
          JOIN hypervisor_instances hi ON h.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ((ht.type_key='vmware' AND h.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND h.run_id IN ({hv_ph})))
         ORDER BY h.memory_total_mb DESC
         LIMIT 40
    """, list(new_vc) + list(new_hv))
    raw_hosts = cur.fetchall()

    cur.execute(f"SELECT COUNT(*) AS t FROM vms WHERE run_id IN ({vc_ph})", tuple(new_vc))
    vmware_vms = int(cur.fetchone()["t"] or 0)
    cur.execute(f"SELECT COUNT(*) AS t FROM vms WHERE run_id IN ({hv_ph})", tuple(new_hv))
    hyperv_vms = int(cur.fetchone()["t"] or 0)

    cur.execute(f"""
        SELECT v.name AS vm_name, v.cpu_count, v.memory_mb, v.os_name,
               v.primary_ip, v.power_state, v.total_disk_gb,
               hi.name AS vcenter_name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
         WHERE ((ht.type_key='vmware' AND v.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND v.run_id IN ({hv_ph})))
         ORDER BY v.memory_mb DESC
         LIMIT 30
    """, list(new_vc) + list(new_hv))
    raw_vms = cur.fetchall()

    cur.execute(f"""
        SELECT hi.name AS vcenter_name, COUNT(*) AS c
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id = hi.id
         WHERE v.run_id IN ({vc_ph}) GROUP BY hi.name ORDER BY c DESC
    """, tuple(new_vc))
    vcenter_vms = {r["vcenter_name"]: int(r["c"]) for r in cur.fetchall()}

    cur.execute(f"""
        SELECT hi.name AS vcenter_name, COUNT(*) AS c
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id = hi.id
         WHERE c.run_id IN ({vc_ph}) GROUP BY hi.name
    """, tuple(new_vc))
    vcenter_clusters = {r["vcenter_name"]: int(r["c"]) for r in cur.fetchall()}

    cur.close(); conn.close()

    all_clusters = [_mk_cluster(r, r["platform"], r["vcenter_name"]) for r in raw_clusters]
    all_ds = [_mk_ds(r, r["platform"]) for r in raw_ds]

    return {
        "clusters": all_clusters,
        "datastores": all_ds,
        "hosts": raw_hosts,
        "vms": raw_vms,
        "vmware_vms": vmware_vms,
        "hyperv_vms": hyperv_vms,
        "total_vms": vmware_vms + hyperv_vms,
        "n_clusters": len(all_clusters),
        "n_datastores": len(all_ds),
        "n_hosts": len(raw_hosts),
        "vcenter_vms": vcenter_vms,
        "vcenter_clusters": vcenter_clusters,
    }


# ── /api/ai/ask ────────────────────────────────────────────────
@app.route("/api/ai/ask", methods=["POST"])
@login_required
def ai_ask():
    import re, traceback

    req_data = request.json or {}
    question = req_data.get("question", "").strip()
    if not question:
        return jsonify({"error": "No question provided"}), 400
    q = question.lower()

    # ── identity ──────────────────────────────────────────────
    if _kw(q, "what is your name", "who are you", "your name",
              "what can you do", "help me", "how can you help",
              "introduce yourself", "hello", "hi ", "hey ",
              "good morning", "good afternoon", "good evening"):
        return jsonify({"question": question, "answer": (
            f"👋 Hello! I'm **{AGENT_NAME}**.\n\n{AGENT_DESC}\n\n"
            "**What I can do:**\n"
            "  • VM / cluster / host / datastore counts and details\n"
            "  • CPU, RAM, storage usage — current and trends\n"
            "  • Historical reports\n"
            "  • Capacity recommendations\n"
            "  • VM placement suggestions\n"
            "  • Full / CPU / memory / datastore / host reports (CSV)\n"
            "  • Compare VMware vs Hyper-V\n"
            "  • Predict next CPU usage (after ML training)\n\n"
            "Just type your question!")})

    try:
        D = _ai_load_dataset()
        all_clusters = D["clusters"]
        all_ds = D["datastores"]
        all_hosts = D["hosts"]
        all_vms = D["vms"]
        vmware_vms = D["vmware_vms"]
        hyperv_vms = D["hyperv_vms"]
        total_vms = D["total_vms"]
        n_clusters = D["n_clusters"]
        n_ds = D["n_datastores"]
        n_hosts = D["n_hosts"]
        vcenter_vms = D["vcenter_vms"]
        vcenter_clusters = D["vcenter_clusters"]

        vmw_cls = [c for c in all_clusters if c["platform"] == "VMware"]
        hv_cls  = [c for c in all_clusters if c["platform"] == "Hyper-V"]

        def _tbl(title, cols, rows):
            return {"type": "table", "title": title,
                    "columns": cols, "rows": list(rows)}

        CLS_COLS = [
            {"key":"name","label":"Cluster"},{"key":"platform","label":"Platform"},
            {"key":"vcenter","label":"vCenter"},{"key":"num_hosts","label":"Hosts"},
            {"key":"num_vms","label":"VMs"},
            {"key":"cpu_usage","label":"CPU %","type":"bar"},
            {"key":"free_cpu_ghz","label":"Free CPU GHz"},
            {"key":"mem_usage","label":"RAM %","type":"bar"},
            {"key":"free_ram_gb","label":"Free RAM GB"},
            {"key":"storage_usage","label":"Stor %","type":"bar"},
            {"key":"free_storage_tb","label":"Free Stor TB"},
        ]
        DS_COLS = [
            {"key":"name","label":"Datastore"},{"key":"platform","label":"Platform"},
            {"key":"cluster","label":"Cluster"},{"key":"capacity_gb","label":"Cap GB"},
            {"key":"used_gb","label":"Used GB"},{"key":"free_gb","label":"Free GB"},
            {"key":"free_percent","label":"Free %","type":"bar"},
            {"key":"used_percent","label":"Used %","type":"badge"},
        ]

        # ── direct-answer engine ──────────────────────────────
        # Reports
        if _kw(q, "full report", "infrastructure report", "complete report"):
            high_cpu = [c for c in all_clusters if c["cpu_usage"] > 80]
            crit_ds  = [d for d in all_ds if d["free_percent"] < 10]
            summary = [
                {"label":"Total VMs","value":total_vms,"status":"ok"},
                {"label":"VMware VMs","value":vmware_vms,"status":"ok"},
                {"label":"Hyper-V VMs","value":hyperv_vms,"status":"ok"},
                {"label":"Clusters","value":n_clusters,"status":"ok"},
                {"label":"Hosts","value":n_hosts,"status":"ok"},
                {"label":"Datastores","value":n_ds,"status":"ok"},
                {"label":">80% CPU","value":len(high_cpu),"status":"crit" if high_cpu else "ok"},
                {"label":"DS <10% free","value":len(crit_ds),"status":"crit" if crit_ds else "ok"},
            ]
            note_parts = []
            if high_cpu: note_parts.append("⚠ High CPU: " + ", ".join(c["name"] for c in high_cpu))
            if crit_ds:  note_parts.append("🔴 Critical DS: " + ", ".join(d["name"] for d in crit_ds))
            return jsonify({"question": question, "report": {
                "type":"full", "title":"Full Infrastructure Report",
                "summary": summary,
                "note": "  ".join(note_parts) or "✓ All systems healthy.",
                "sections":[
                    {**_tbl("Clusters", CLS_COLS,
                            sorted(all_clusters, key=lambda x: -x["cpu_usage"])),
                     "title":"Clusters"},
                    {**_tbl("Datastores", DS_COLS,
                            sorted(all_ds, key=lambda x: x["free_percent"])),
                     "title":"Datastores"},
                ],
            }})

        if _kw(q, "cluster report", "clusters report"):
            return jsonify({"question": question, "report": _tbl(
                "Cluster Report", CLS_COLS,
                sorted(all_clusters, key=lambda x: -x["cpu_usage"]))})
        if _kw(q, "datastore report", "datastores report", "storage report"):
            return jsonify({"question": question, "report": _tbl(
                "Datastore Report", DS_COLS,
                sorted(all_ds, key=lambda x: x["free_percent"]))})
        if _kw(q, "cpu report"):
            cols = CLS_COLS[:7]
            return jsonify({"question": question, "report": _tbl(
                "CPU Report", cols,
                sorted(all_clusters, key=lambda x: -x["cpu_usage"]))})
        if _kw(q, "memory report", "mem report", "ram report"):
            cols = [
                {"key":"name","label":"Cluster"},{"key":"platform","label":"Platform"},
                {"key":"vcenter","label":"vCenter"},
                {"key":"mem_usage","label":"RAM %","type":"bar"},
                {"key":"free_ram_gb","label":"Free RAM GB"},
                {"key":"total_ram_gb","label":"Total RAM GB"},
            ]
            return jsonify({"question": question, "report": _tbl(
                "Memory Report", cols,
                sorted(all_clusters, key=lambda x: -x["mem_usage"]))})

        # Counts
        if _kw(q, "how many vm", "total vm", "number of vm", "vm count"):
            if _kw(q, "vmware") and not _kw(q, "hyper"):
                return jsonify({"question": question, "answer": f"VMware VMs: **{vmware_vms}**"})
            if _kw(q, "hyper-v", "hyperv", "hyper v"):
                return jsonify({"question": question, "answer": f"Hyper-V VMs: **{hyperv_vms}**"})
            lines = [f"Total VMs: **{total_vms}** ({vmware_vms} VMware + {hyperv_vms} Hyper-V)\n"]
            for vc, cnt in sorted(vcenter_vms.items(), key=lambda x: -x[1]):
                lines.append(f"  • {vc}: {cnt} VMs")
            return jsonify({"question": question, "answer": "\n".join(lines)})

        if _kw(q, "how many cluster", "number of cluster", "cluster count"):
            return jsonify({"question": question,
                            "answer": f"Total clusters: **{n_clusters}** ({len(vmw_cls)} VMware + {len(hv_cls)} Hyper-V)"})

        if _kw(q, "how many host", "number of host", "host count"):
            return jsonify({"question": question, "answer": f"Total hosts: **{n_hosts}**"})

        if _kw(q, "how many datastore", "number of datastore", "datastore count"):
            return jsonify({"question": question, "answer": f"Total datastores: **{n_ds}**"})

        # Extremes
        if _kw(q, "highest cpu", "most cpu", "busiest cluster"):
            c = max(all_clusters, key=lambda x: x["cpu_usage"], default=None)
            if c: return jsonify({"question": question,
                                  "answer": f"Highest CPU: **{c['name']}** ({c['platform']}, {c['vcenter']}) — {c['cpu_usage']}%"})

        if _kw(q, "fullest datastore", "most full datastore"):
            d = min(all_ds, key=lambda x: x["free_percent"], default=None)
            if d: return jsonify({"question": question,
                                  "answer": f"Fullest: **{d['name']}** ({d['platform']}, {d['cluster']}) — {d['used_percent']}% used"})

        if _kw(q, "most free cpu", "free cpu", "lowest cpu", "idle cluster"):
            top = sorted(all_clusters, key=lambda x: -x["free_cpu_ghz"])[:5]
            lines = ["Clusters with most free CPU:"]
            for c in top:
                lines.append(f"  • {c['name']} ({c['platform']}): {c['free_cpu_ghz']} GHz free (used {c['cpu_usage']}%)")
            return jsonify({"question": question, "answer": "\n".join(lines)})

        # Threshold queries
        m = re.search(r"cpu\s*(?:above|over|>|greater than)\s*(\d+)", q)
        if m:
            thr = int(m.group(1))
            hits = sorted([c for c in all_clusters if c["cpu_usage"] > thr], key=lambda x: -x["cpu_usage"])
            if not hits: return jsonify({"question": question, "answer": f"No clusters with CPU above {thr}%. ✓"})
            lines = [f"Clusters with CPU > {thr}%:"]
            for c in hits:
                lines.append(f"  • {c['name']} ({c['platform']}): {c['cpu_usage']}%")
            return jsonify({"question": question, "answer": "\n".join(lines)})

        m = re.search(r"(?:datastore|storage|disk).*?(?:below|less than|<)\s*(\d+)\s*%", q)
        if m:
            thr = int(m.group(1))
            hits = sorted([d for d in all_ds if d["free_percent"] < thr], key=lambda x: x["free_percent"])
            if not hits: return jsonify({"question": question, "answer": f"No datastores below {thr}% free. ✓"})
            lines = [f"Datastores below {thr}% free:"]
            for d in hits:
                lines.append(f"  • {d['name']} ({d['platform']}, {d['cluster']}): {d['free_percent']}% free ({d['free_gb']}/{d['capacity_gb']} GB)")
            return jsonify({"question": question, "answer": "\n".join(lines)})

        # Health summary
        if _kw(q, "health", "overview", "summary", "status", "how is", "overall", "infrastructure"):
            high_cpu = [c for c in all_clusters if c["cpu_usage"] > 80]
            high_mem = [c for c in all_clusters if c["mem_usage"] > 80]
            crit_ds  = [d for d in all_ds if d["free_percent"] < 10]
            warn_ds  = [d for d in all_ds if 10 <= d["free_percent"] < 20]
            metrics = [
                {"label":"Total VMs","value":total_vms,"status":"ok"},
                {"label":"VMware VMs","value":vmware_vms,"status":"ok"},
                {"label":"Hyper-V VMs","value":hyperv_vms,"status":"ok"},
                {"label":"Clusters","value":n_clusters,"status":"ok"},
                {"label":"Hosts","value":n_hosts,"status":"ok"},
                {"label":"Datastores","value":n_ds,"status":"ok"},
                {"label":">80% CPU","value":len(high_cpu),"status":"crit" if high_cpu else "ok"},
                {"label":">80% RAM","value":len(high_mem),"status":"warn" if high_mem else "ok"},
                {"label":"DS <10% free","value":len(crit_ds),"status":"crit" if crit_ds else "ok"},
                {"label":"DS <20% free","value":len(warn_ds),"status":"warn" if warn_ds else "ok"},
            ]
            note_parts = []
            if high_cpu: note_parts.append("⚠ High CPU: " + ", ".join(c["name"] for c in high_cpu))
            if high_mem: note_parts.append("⚠ High RAM: " + ", ".join(c["name"] for c in high_mem))
            if crit_ds:  note_parts.append("🔴 Critical DS: " + ", ".join(d["name"] for d in crit_ds))
            return jsonify({"question": question, "report": {
                "type":"metrics","title":"Infrastructure Overview",
                "metrics":metrics,
                "note": "  ".join(note_parts) or "✓ All systems within healthy thresholds.",
            }})

        # Placement
        if _kw(q, "where should i place", "where to place", "where can i place",
                  "suggest placement", "best cluster for", "place a vm",
                  "place new vm", "recommend cluster", "placement for"):
            cpu = 2; ram = 4; stor = 50; plat = "any"
            mc = re.search(r"(\d+)\s*(?:vcpu|vcore|cpu|core)", q)
            if mc: cpu = int(mc.group(1))
            mr = re.search(r"(\d+)\s*gb\s*(?:ram|memory|mem)", q)
            if mr: ram = int(mr.group(1))
            ms = re.search(r"(\d+)\s*gb\s*(?:disk|storage|stor)", q)
            if ms: stor = int(ms.group(1))
            if "vmware" in q: plat = "vmware"
            elif _kw(q, "hyper-v", "hyperv"): plat = "hyperv"
            reqs = {"cpu_cores":cpu,"ram_gb":ram,"storage_gb":stor,"platform":plat}
            try:
                sug = get_vm_placement_suggestions(reqs)
            except Exception:
                sug = []
            clean = []
            for s in sug:
                s2 = dict(s)
                s2["total_score"] = float(s2.get("total_score") or 0)
                ar = s2.get("available_resources", {})
                s2["available_resources"] = {k: float(v or 0) for k, v in ar.items()}
                clean.append(s2)
            return jsonify({"question": question, "report": {
                "type":"placement","requirements":reqs,
                "suggestions":clean[:5],"total_candidates":len(clean),
            }})

        # ── LLM fallback with REAL data ────────────────────────
        # This is the fix: give the model actual rows, not just counts.
        top_clusters = sorted(all_clusters, key=lambda x: -x["cpu_usage"])[:12]
        cluster_lines = []
        for c in top_clusters:
            cluster_lines.append(
                f"  [{c['platform']}] {c['name']} (vCenter: {c['vcenter']}) "
                f"CPU {c['cpu_usage']}% free {c['free_cpu_ghz']}GHz | "
                f"RAM {c['mem_usage']}% free {c['free_ram_gb']}GB | "
                f"Storage {c['storage_usage']}% free {c['free_storage_tb']}TB | "
                f"hosts {c['num_hosts']} | VMs {c['num_vms']}")

        ds_lines = []
        for d in sorted(all_ds, key=lambda x: x["free_percent"])[:12]:
            ds_lines.append(
                f"  [{d['platform']}] {d['name']} (cluster: {d['cluster']}) "
                f"free {d['free_gb']}GB ({d['free_percent']}%)")

        host_lines = []
        for h in all_hosts[:10]:
            host_lines.append(
                f"  [{h['platform']}] {h['host_name']} (vCenter: {h.get('vcenter_name') or '-'}) "
                f"CPU {h.get('cpu_cores','?')} cores | "
                f"RAM {h.get('memory_total_gb','?')}GB total, {h.get('memory_used_gb','?')}GB used | "
                f"VMs {h.get('num_vms','?')}")

        vm_lines = []
        for v in all_vms[:10]:
            vm_lines.append(
                f"  [{v['platform']}] {v['vm_name']} "
                f"({v['cpu_count'] or '?'} vCPU, "
                f"{round((v['memory_mb'] or 0)/1024)}GB RAM, "
                f"{v['os_name'] or '?'}, {v['power_state'] or '?'})")

        prompt = (
            f"You are {AGENT_NAME}, an expert AI assistant for a VMware and "
            f"Hyper-V data centre. Answer the question using ONLY the data "
            f"below. If the data is insufficient, say so — do NOT invent "
            f"facts, numbers, or infrastructure that is not listed. "
            f"Be concise and factual.\n\n"
            f"=== ENVIRONMENT TOTALS ===\n"
            f"VMs: {total_vms} ({vmware_vms} VMware / {hyperv_vms} Hyper-V)\n"
            f"Clusters: {n_clusters} | Hosts: {n_hosts} | Datastores: {n_ds}\n\n"
            f"=== CLUSTERS (sorted by CPU usage) ===\n"
            + "\n".join(cluster_lines) + "\n\n"
            f"=== DATASTORES (sorted by free % asc) ===\n"
            + "\n".join(ds_lines) + "\n\n"
            f"=== HOSTS (top 10 by RAM) ===\n"
            + "\n".join(host_lines) + "\n\n"
            f"=== VMs (top 10 by RAM) ===\n"
            + "\n".join(vm_lines) + "\n\n"
            f"=== QUESTION ===\n{question}\n\n"
            f"Answer (facts only, from the data above):"
        )

        llm_ans = _llm(prompt)
        if not llm_ans:
            llm_ans = (
                f"I have data for {total_vms} VMs, {n_clusters} clusters, "
                f"{n_hosts} hosts and {n_ds} datastores, but the local LLM is "
                f"not responding. Try one of these direct queries instead:\n"
                f"  • 'how many VMs'\n"
                f"  • 'highest CPU cluster'\n"
                f"  • 'full report'\n"
                f"  • 'infrastructure overview'"
            )
        return jsonify({"question": question, "answer": llm_ans})

    except Exception:
        logger.error("AI ask error:\n%s", traceback.format_exc())
        return jsonify({"error": "Internal server error — check Flask logs."}), 500


# ── /api/ai/train_models ──────────────────────────────────────
@app.route("/api/ai/train_models", methods=["GET", "POST"])
@login_required
@superadmin_required
def ai_train_models():
    """
    Train CPU forecasting models for every cluster that has enough history.
    Reads only unified tables. Called by the HTML 'Train ML Models' button.
    """
    conn = get_db_connection(); cur = conn.cursor()
    results = []

    def _train(key, rows):
        hist = [{"run_timestamp": r["ts"], "cpu_usage_percent": float(r["pct"] or 0)}
                for r in rows if r.get("pct") is not None]
        if len(hist) >= 4:
            m = train_cpu_forecast_model(key, hist)
            return "trained" if m else "failed"
        return "insufficient data"

    cur.execute("SELECT DISTINCT name FROM clusters WHERE name IS NOT NULL")
    for row in cur.fetchall():
        cn = row["name"]
        cur.execute("""
            SELECT cr.started_at AS ts, c.cpu_usage_percent AS pct
              FROM clusters c
              JOIN collection_runs cr ON c.run_id = cr.id
             WHERE c.name = %s
             ORDER BY cr.started_at ASC
             LIMIT 60
        """, (cn,))
        results.append({"entity": f"[Cluster] {cn}",
                        "status": _train(cn, cur.fetchall())})

    cur.close(); conn.close()
    trained = sum(1 for r in results if r["status"] == "trained")
    return jsonify({"results": results, "trained": trained, "total": len(results)})


# ── /api/ai/compare_insight ───────────────────────────────────
@app.route("/api/ai/compare_insight", methods=["POST"])
@login_required
def ai_compare_insight():
    """
    Called by the chat when the user writes:
      compare cluster X between DATE1 and DATE2 vs DATE3 and DATE4
    Returns { insight, comparison } — the comparison is rendered as a table
    by the chat, and the insight is a one-line LLM summary.
    """
    from datetime import datetime

    data = request.json or {}
    cluster = data.get("cluster")
    start1  = data.get("start1"); end1 = data.get("end1")
    start2  = data.get("start2"); end2 = data.get("end2")
    if not all([cluster, start1, end1, start2, end2]):
        return jsonify({"error": "Missing parameters"}), 400

    conn = get_db_connection(); cur = conn.cursor()

    def stats(start, end):
        cur.execute("""
            SELECT c.cpu_usage_percent, c.memory_usage_percent, c.storage_usage_percent,
                   cr.started_at AS run_timestamp
              FROM clusters c
              JOIN collection_runs cr ON c.run_id = cr.id
             WHERE c.name = %s AND cr.started_at BETWEEN %s AND %s
             ORDER BY cr.started_at ASC
        """, (cluster, start, end))
        return cur.fetchall()

    def calc(vals):
        if not vals:
            return {"avg": 0, "min": 0, "max": 0, "trend": 0}
        avg = sum(vals) / len(vals)
        if len(vals) > 1:
            x = list(range(len(vals)))
            n = len(x)
            denom = n * sum(xi * xi for xi in x) - sum(x) ** 2
            slope = ((n * sum(x[i] * vals[i] for i in range(n)) - sum(x) * sum(vals))
                     / denom) if denom else 0
        else:
            slope = 0
        return {"avg": round(avg, 1), "min": round(min(vals), 1),
                "max": round(max(vals), 1), "trend": round(slope, 2)}

    def build(rows):
        details = [{"timestamp": str(r["run_timestamp"])[:16],
                    "cpu":     round(float(r["cpu_usage_percent"] or 0), 1),
                    "memory":  round(float(r["memory_usage_percent"] or 0), 1),
                    "storage": round(float(r["storage_usage_percent"] or 0), 1),
                    "vm_count": 0} for r in rows]
        return {
            "cpu":      calc([d["cpu"] for d in details]),
            "memory":   calc([d["memory"] for d in details]),
            "storage":  calc([d["storage"] for d in details]),
            "vm_count": 0, "vm_count_start": 0, "vm_count_end": 0,
            "data_points": len(rows),
            "details": details,
        }

    p1_rows = stats(start1, end1)
    p2_rows = stats(start2, end2)
    cur.close(); conn.close()

    if not p1_rows or not p2_rows:
        return jsonify({"error": "No data for this cluster in the selected periods"}), 404

    pa = build(p1_rows); pb = build(p2_rows)

    def delta(a, b):
        if a == 0: return 0
        return round(((b - a) / a) * 100, 1)

    comparison = {
        "cluster": cluster,
        "period1": {"start": start1[:10], "end": end1[:10], **pa},
        "period2": {"start": start2[:10], "end": end2[:10], **pb},
        "deltas": {
            "cpu":     delta(pa["cpu"]["avg"],     pb["cpu"]["avg"]),
            "memory":  delta(pa["memory"]["avg"],  pb["memory"]["avg"]),
            "storage": delta(pa["storage"]["avg"], pb["storage"]["avg"]),
            "vm_count": 0,
        },
    }

    # One-line insight via LLM (falls back to a template)
    prompt = (
        f"Write ONE short sentence (max 20 words) about this cluster change. "
        f"Cluster {cluster} period1 {start1[:10]} to {end1[:10]} vs "
        f"period2 {start2[:10]} to {end2[:10]}. "
        f"CPU changed {comparison['deltas']['cpu']:+}%, "
        f"memory {comparison['deltas']['memory']:+}%, "
        f"storage {comparison['deltas']['storage']:+}%. "
        f"If CPU/RAM went up, suggest investigation."
    )
    insight = _llm(prompt)
    if not insight:
        parts = []
        for k in ("cpu", "memory", "storage"):
            v = comparison["deltas"][k]
            if v != 0:
                parts.append(f"{k.upper()} {v:+}%")
        insight = (", ".join(parts) + ". Check the trend for capacity planning."
                   if parts else "No significant change between the two periods.")

    return jsonify({"insight": insight, "comparison": comparison})


# ── /api/ai/reporting_insight (kept for compatibility) ────────
@app.route("/api/ai/reporting_insight", methods=["POST"])
@login_required
def ai_reporting_insight():
    return jsonify({"insight": "Use /api/ai/compare_insight for per-cluster insights."})


# ── /ai_chat page ──────────────────────────────────────────────
@app.route("/ai_chat")
@login_required
def ai_chat():
    return render_template("ai_chat.html")






#_____________________________________________________________

from werkzeug.utils import secure_filename
import re as _re_docs


# ─────────────────────────────────────────────────────────────
#  DOCUMENT ANALYST MODE
# ─────────────────────────────────────────────────────────────
UPLOAD_ROOT = getattr(config, "UPLOAD_DIR", "uploads")
DOCS_DIR    = os.path.join(UPLOAD_ROOT, "documents")
REPORTS_DIR = os.path.join(UPLOAD_ROOT, "reports")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Flask's per-request upload cap
app.config["MAX_CONTENT_LENGTH"] = getattr(config, "DOCS_MAX_MB", 50) * 1024 * 1024

# Recognised extensions and their extractors
PLAIN_EXTS = {"txt", "md", "markdown", "log", "csv", "tsv", "json",
              "yaml", "yml", "xml", "html", "htm", "ini", "conf", "sql", "env"}


def _extract_text(path, filename):
    """Return plain text extracted from an uploaded document, or an error string."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    try:
        if ext == "pdf":
            from pypdf import PdfReader
            reader = PdfReader(path)
            pages = [(p.extract_text() or "") for p in reader.pages]
            return "\n\n".join(pages)
        if ext == "docx":
            from docx import Document
            doc = Document(path)
            return "\n".join(p.text for p in doc.paragraphs if p.text is not None)
        if ext == "xlsx":
            from openpyxl import load_workbook
            wb = load_workbook(path, read_only=True, data_only=True)
            lines = []
            for ws in wb.worksheets:
                lines.append(f"\n### Sheet: {ws.title}\n")
                for row in ws.iter_rows(values_only=True):
                    lines.append("\t".join("" if c is None else str(c) for c in row))
            wb.close()
            return "\n".join(lines)
        if ext in PLAIN_EXTS:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        # last resort: try to read as utf-8
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    except Exception as e:
        return f"[Could not extract text from {filename}: {e}]"


def _strip_thinking(text):
    """Qwen3 can emit  thinking... blocks; strip them for clean output."""
    if not text:
        return text
    return _re_docs.sub(r" thinking.*?", "", text, flags=_re_docs.DOTALL).strip()


def _qwen(prompt, max_tokens=2500, temperature=0.3):
    """Call the local qwen3-14b model. Returns text or an error string."""
    import requests as _rq
    try:
        r = _rq.post(
            getattr(config, "OLLAMA_URL", "http://localhost:11434/api/generate"),
            json={
                "model": getattr(config, "QWEN_MODEL", "qwen3-14b-local:latest"),
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_ctx": 32768,
                    "num_predict": max_tokens,
                },
            },
            timeout=900,
        )
        if r.status_code == 200:
            return _strip_thinking(r.json().get("response", "").strip())
        return f"[LLM error: HTTP {r.status_code} — {r.text[:200]}]"
    except Exception as e:
        return f"[LLM error: {e}]"


def _pick_relevant_context(doc_rows, question, max_chars=None):
    """
    Simple keyword-overlap retrieval over the uploaded documents.
    Returns a single concatenated context string.
    """
    max_chars = max_chars or getattr(config, "DOCS_CONTEXT_CHARS", 24000)
    if not doc_rows:
        return ""

    stop = {"the","a","an","is","are","was","were","of","to","in","on","and","or",
            "for","with","what","how","why","when","where","which","who","this",
            "that","these","those","it","its","be","been","has","have","had"}
    q_words = set(w for w in _re_docs.findall(r"\w+", question.lower()) if w not in stop and len(w) > 2)

    scored = []
    for d in doc_rows:
        text = d.get("text_content") or ""
        if not text:
            continue
        doc_words = set(_re_docs.findall(r"\w+", text.lower()))
        overlap = len(q_words & doc_words) if q_words else 0
        # Prefer overlap, then shorter docs (denser signal)
        scored.append((overlap, len(text), d["id"], d["filename"], text))
    scored.sort(key=lambda x: (-x[0], x[1]))

    chunks, total = [], 0
    for score, size, doc_id, filename, text in scored:
        header = f"\n\n--- Document: {filename} ---\n"
        # If the doc alone is bigger than the budget, cut it down
        remaining = max_chars - total - len(header)
        if remaining < 500 and chunks:
            break
        body = text if len(text) <= remaining else text[:remaining] + "\n[...truncated...]"
        piece = header + body
        chunks.append(piece)
        total += len(piece)
        if total >= max_chars:
            break
    return "".join(chunks)


# ── upload ─────────────────────────────────────────────────────
@app.route("/api/docs/upload", methods=["POST"])
@login_required
def api_docs_upload():
    files = request.files.getlist("files") or []
    if not files:
        f = request.files.get("file")
        if f:
            files = [f]
    if not files:
        return jsonify({"error": "No files in the request"}), 400

    max_bytes = getattr(config, "DOCS_MAX_MB", 50) * 1024 * 1024
    conn = get_db_connection(); cur = conn.cursor()
    saved = []
    errors = []

    for f in files:
        if not f.filename:
            continue
        original = secure_filename(f.filename) or f"upload_{uuid.uuid4().hex}"
        unique = f"{uuid.uuid4().hex[:8]}_{original}"
        dest = os.path.join(DOCS_DIR, unique)

        # Save to disk first
        f.save(dest)
        size = os.path.getsize(dest)

        if size > max_bytes:
            os.remove(dest)
            errors.append(f"{original}: file exceeds {max_bytes // (1024*1024)} MB limit")
            continue

        # Extract text
        text = _extract_text(dest, original)
        # Cap stored text at 5M chars (about 5MB of text)
        if len(text) > 5_000_000:
            text = text[:5_000_000] + "\n[...truncated...]"

        mime = (f.mimetype or "application/octet-stream")[:150]
        try:
            cur.execute("""
                INSERT INTO uploaded_documents
                  (filename, stored_name, mime_type, size_bytes,
                   uploaded_by, text_length, text_content)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (original, unique, mime, size,
                  session.get("username"), len(text), text))
            doc_id = cur.lastrowid
            saved.append({
                "id": doc_id, "filename": original, "size_bytes": size,
                "text_length": len(text),
            })
        except Exception as e:
            try: os.remove(dest)
            except OSError: pass
            errors.append(f"{original}: DB insert failed — {e}")

    cur.close(); conn.close()
    return jsonify({"saved": saved, "errors": errors})


# ── list / delete ──────────────────────────────────────────────
@app.route("/api/docs/list")
@login_required
def api_docs_list():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT id, filename, mime_type, size_bytes, uploaded_by,
               uploaded_at, text_length
          FROM uploaded_documents
         ORDER BY uploaded_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r.get("uploaded_at"): r["uploaded_at"] = r["uploaded_at"].isoformat()
    return jsonify(rows)


@app.route("/api/docs/<int:doc_id>", methods=["DELETE"])
@login_required
@superadmin_required
def api_docs_delete(doc_id):
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT stored_name FROM uploaded_documents WHERE id=%s", (doc_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"error": "Not found"}), 404
    cur.execute("DELETE FROM uploaded_documents WHERE id=%s", (doc_id,))
    cur.close(); conn.close()
    try:
        os.remove(os.path.join(DOCS_DIR, row["stored_name"]))
    except OSError:
        pass
    return jsonify({"ok": True})


@app.route("/api/docs/download/<int:doc_id>")
@login_required
def api_docs_download(doc_id):
    from flask import send_from_directory
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT filename, stored_name FROM uploaded_documents WHERE id=%s", (doc_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return "Not found", 404
    return send_from_directory(DOCS_DIR, row["stored_name"],
                               as_attachment=True, download_name=row["filename"])


# ── analyze (Q&A over selected docs) ──────────────────────────
@app.route("/api/docs/ask", methods=["POST"])
@login_required
def api_docs_ask():
    data = request.json or {}
    question = (data.get("question") or "").strip()
    doc_ids = data.get("doc_ids") or []
    if not question:
        return jsonify({"error": "No question provided"}), 400

    conn = get_db_connection(); cur = conn.cursor()
    if doc_ids:
        ph = ",".join(["%s"] * len(doc_ids))
        cur.execute(f"""
            SELECT id, filename, text_content
              FROM uploaded_documents
             WHERE id IN ({ph})
        """, doc_ids)
    else:
        cur.execute("SELECT id, filename, text_content FROM uploaded_documents ORDER BY uploaded_at DESC")
    docs = cur.fetchall()
    cur.close(); conn.close()

    if not docs:
        return jsonify({"error": "No documents uploaded yet. Upload some first."}), 400

    context = _pick_relevant_context(docs, question)
    prompt = (
        "You are a document analyst. Answer the user's question using ONLY "
        "the documents provided below. Quote short excerpts when useful. "
        "If the answer is not in the documents, say so explicitly — do NOT "
        "invent facts. Be concise but thorough.\n\n"
        f"=== DOCUMENTS ({len(docs)} file(s)) ===\n{context}\n\n"
        f"=== QUESTION ===\n{question}\n\n"
        "=== ANSWER ==="
    )
    answer = _qwen(prompt, max_tokens=2000, temperature=0.2)
    return jsonify({
        "question": question,
        "answer": answer,
        "docs_used": [{"id": d["id"], "filename": d["filename"]} for d in docs],
    })


# ── generate report ────────────────────────────────────────────
@app.route("/api/docs/report", methods=["POST"])
@login_required
def api_docs_report():
    import datetime as _dt
    data = request.json or {}
    instruction = (data.get("instruction") or "").strip()
    title       = (data.get("title") or "").strip()
    doc_ids     = data.get("doc_ids") or []
    fmt         = (data.get("format") or "md").lower()

    if not title:
        title = f"Report — {_dt.datetime.now():%Y-%m-%d %H:%M}"

    conn = get_db_connection(); cur = conn.cursor()
    if doc_ids:
        ph = ",".join(["%s"] * len(doc_ids))
        cur.execute(f"SELECT id, filename, text_content FROM uploaded_documents WHERE id IN ({ph})", doc_ids)
    else:
        cur.execute("SELECT id, filename, text_content FROM uploaded_documents ORDER BY uploaded_at DESC")
    docs = cur.fetchall()
    cur.close(); conn.close()

    if not docs:
        return jsonify({"error": "No documents uploaded yet."}), 400

    context = _pick_relevant_context(docs, instruction or title, max_chars=getattr(config, "DOCS_CONTEXT_CHARS", 24000))

    prompt = (
        "You are a senior technical writer. Produce a thorough, well-structured "
        "report based ONLY on the source documents below. Follow the user's "
        "instruction. Use Markdown with clear headings, bullet lists and "
        "tables where appropriate. Do NOT invent facts.\n\n"
        f"=== REPORT TITLE ===\n{title}\n\n"
        f"=== INSTRUCTION ===\n{instruction or 'Summarize and analyze these documents.'}\n\n"
        f"=== SOURCE DOCUMENTS ({len(docs)} file(s)) ===\n{context}\n\n"
        "=== REPORT ===\n"
    )
    body = _qwen(prompt, max_tokens=4000, temperature=0.35)

    # Save the report to disk
    slug = _re_docs.sub(r"[^A-Za-z0-9_.-]", "_", title)[:60] or "report"
    stored_name = f"{_dt.datetime.now():%Y%m%d_%H%M%S}_{slug}.{fmt}"
    full_path = os.path.join(REPORTS_DIR, stored_name)

    if fmt == "html":
        from html import escape as _esc
        content = (f"<!doctype html><meta charset='utf-8'>"
                   f"<title>{_esc(title)}</title>"
                   f"<style>body{{font-family:sans-serif;max-width:900px;margin:2rem auto;"
                   f"padding:0 1rem;line-height:1.6}}pre{{background:#f5f5f5;padding:1rem}}"
                   f"</style><h1>{_esc(title)}</h1><pre>{_esc(body)}</pre>")
    else:
        content = f"# {title}\n\n{body}\n"

    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)
    size = os.path.getsize(full_path)

    # Record it
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO generated_reports
          (title, stored_name, created_by, source_doc_ids, prompt, size_bytes)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (title, stored_name, session.get("username"),
          json.dumps([d["id"] for d in docs]),
          instruction, size))
    report_id = cur.lastrowid
    cur.close(); conn.close()

    return jsonify({
        "id": report_id,
        "title": title,
        "body": body,               # preview in the chat
        "download_url": f"/api/docs/report/{report_id}/download",
        "format": fmt,
        "size_bytes": size,
    })


@app.route("/api/docs/report/<int:report_id>/download")
@login_required
def api_docs_report_download(report_id):
    from flask import send_from_directory
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT title, stored_name FROM generated_reports WHERE id=%s", (report_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return "Not found", 404
    return send_from_directory(REPORTS_DIR, row["stored_name"],
                               as_attachment=True, download_name=row["stored_name"])


@app.route("/api/docs/reports")
@login_required
def api_docs_reports_list():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT id, title, stored_name, created_at, created_by, size_bytes
          FROM generated_reports
         ORDER BY created_at DESC LIMIT 50
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r.get("created_at"): r["created_at"] = r["created_at"].isoformat()
    return jsonify(rows)

# ─────────────────────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────────────────────
@app.route("/reporting")
@login_required
def reporting_page():
    return render_template("reporting.html")


@app.route("/api/reporting/overview")
@login_required
def reporting_overview():
    conn = get_db_connection(); cur = conn.cursor()
    new_vc, new_hv = _new_run_ids(None, None)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))

    def cluster_agg(ph, params):
        cur.execute(f"""
            SELECT COUNT(*) AS count,
                   AVG(cpu_usage_percent) AS avg_cpu,
                   AVG(memory_usage_percent) AS avg_mem,
                   AVG(storage_usage_percent) AS avg_storage
              FROM clusters WHERE run_id IN ({ph})
        """, params)
        return cur.fetchone()

    def table_count(table, ph, params):
        cur.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE run_id IN ({ph})", params)
        return cur.fetchone()["count"]

    vmw_cluster = cluster_agg(vc_ph, tuple(new_vc))
    hv_cluster  = cluster_agg(hv_ph, tuple(new_hv))

    vmw_hosts = table_count("hosts", vc_ph, tuple(new_vc))
    vmw_vms   = table_count("vms", vc_ph, tuple(new_vc))
    vmw_ds    = table_count("datastores", vc_ph, tuple(new_vc))
    hv_hosts  = table_count("hosts", hv_ph, tuple(new_hv))
    hv_vms    = table_count("vms", hv_ph, tuple(new_hv))
    hv_ds     = table_count("datastores", hv_ph, tuple(new_hv))

    cur.execute(f"""
        SELECT c.name AS cluster_name,
               COALESCE(c.cpu_usage_percent,0) AS cpu_usage_percent,
               COALESCE(c.memory_usage_percent,0) AS memory_usage_percent,
               COALESCE(c.storage_usage_percent,0) AS storage_usage_percent,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE ((ht.type_key='vmware' AND c.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND c.run_id IN ({hv_ph})))
         ORDER BY platform, c.name
    """, list(new_vc) + list(new_hv))
    all_clusters = cur.fetchall()
    cur.close(); conn.close()

    total_clusters = (vmw_cluster["count"] or 0) + (hv_cluster["count"] or 0)
    total_hosts = vmw_hosts + hv_hosts
    total_vms = vmw_vms + hv_vms
    total_ds = vmw_ds + hv_ds

    def _avg(a, b):
        if total_clusters == 0: return 0
        return round(((a or 0) + (b or 0)) / 2, 1)

    return jsonify({
        "summary": {
            "total_clusters": total_clusters, "total_hosts": total_hosts,
            "total_vms": total_vms, "total_datastores": total_ds,
            "avg_cpu_usage": _avg(vmw_cluster["avg_cpu"], hv_cluster["avg_cpu"]),
            "avg_memory_usage": _avg(vmw_cluster["avg_mem"], hv_cluster["avg_mem"]),
            "avg_storage_usage": _avg(vmw_cluster["avg_storage"], hv_cluster["avg_storage"]),
            "vmware_clusters": vmw_cluster["count"] or 0,
            "hyperv_clusters": hv_cluster["count"] or 0,
            "vmware_hosts": vmw_hosts, "hyperv_hosts": hv_hosts,
            "vmware_vms": vmw_vms, "hyperv_vms": hv_vms,
        },
        "chart": {
            "labels": [f"{c['cluster_name']} ({c['platform']})" for c in all_clusters],
            "cpu_data": [float(c["cpu_usage_percent"]) for c in all_clusters],
            "memory_data": [float(c["memory_usage_percent"]) for c in all_clusters],
            "storage_data": [float(c["storage_usage_percent"]) for c in all_clusters],
        },
    })


@app.route("/api/reporting/clusters_list")
@login_required
def clusters_list():
    conn = get_db_connection(); cur = conn.cursor()
    new_vc, new_hv = _new_run_ids(None, None)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))
    cur.execute(f"""
        SELECT DISTINCT c.name AS name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE ((ht.type_key='vmware' AND c.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND c.run_id IN ({hv_ph})))
    """, list(new_vc) + list(new_hv))
    rows = cur.fetchall()
    cur.close(); conn.close()
    rows.sort(key=lambda x: (x["platform"], x["name"]))
    return jsonify(rows)


@app.route("/api/reporting/cluster_trends")
@login_required
def cluster_trends():
    cluster = request.args.get("cluster")
    runs = int(request.args.get("runs", 10))
    if not cluster:
        return jsonify({"error": "Missing cluster parameter"}), 400
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT cr.legacy_run_id AS run_id, cr.started_at AS run_timestamp,
               c.cpu_usage_percent, c.memory_usage_percent, c.storage_usage_percent
          FROM clusters c JOIN collection_runs cr ON c.run_id=cr.id
         WHERE c.name=%s
         ORDER BY cr.started_at ASC
    """, (cluster,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    if not rows:
        return jsonify({"error": "Cluster not found"}), 404
    if len(rows) > runs: rows = rows[-runs:]
    return jsonify({
        "cluster": cluster,
        "timestamps": [str(r["run_timestamp"])[:10] for r in rows],
        "cpu":     [float(r["cpu_usage_percent"] or 0) for r in rows],
        "memory":  [float(r["memory_usage_percent"] or 0) for r in rows],
        "storage": [float(r["storage_usage_percent"] or 0) for r in rows],
    })


@app.route("/api/reporting/runs_list")
@login_required
def reporting_runs_list():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT cr.legacy_run_id AS run_id, MIN(cr.started_at) AS run_timestamp,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM collection_runs cr
          JOIN hypervisor_instances hi ON cr.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE cr.legacy_run_id IS NOT NULL
           AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
         GROUP BY cr.legacy_run_id, ht.type_key
         ORDER BY cr.legacy_run_id DESC LIMIT 40
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    for r in rows:
        if r["run_timestamp"]: r["run_timestamp"] = str(r["run_timestamp"])[:16]
    rows.sort(key=lambda x: x["run_timestamp"] or "", reverse=True)
    return jsonify(rows)


@app.route("/api/reporting/environments_list")
@login_required
def reporting_environments_list():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT hi.name AS name,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM hypervisor_instances hi
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE hi.deleted_at IS NULL AND hi.enabled = 1 AND ht.enabled = 1
         ORDER BY ht.type_key, hi.name
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(rows)


def _get_reporting_changes_data(args):
    conn = get_db_connection(); cur = conn.cursor()

    def runs_for(type_key):
        cur.execute("""
            SELECT MIN(cr.started_at) AS ts,
                   cr.legacy_run_id AS legacy_id,
                   MAX(cr.id) AS new_id
              FROM collection_runs cr
              JOIN hypervisor_instances hi ON cr.hypervisor_instance_id=hi.id
              JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
             WHERE ht.type_key=%s AND cr.legacy_run_id IS NOT NULL
               AND hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
             GROUP BY cr.legacy_run_id
             ORDER BY cr.legacy_run_id DESC
             LIMIT 20
        """, (type_key,))
        return cur.fetchall()

    vc_runs = runs_for("vmware")
    hv_runs = runs_for("hyperv")
    vc_prev_offset = int(args.get("vc_prev_offset", 1))
    hv_prev_offset = int(args.get("hv_prev_offset", 1))

    def pick(runs, offset):
        if len(runs) > offset: return runs[0], runs[offset]
        return (runs[0], None) if runs else (None, None)

    vc_curr, vc_prev = pick(vc_runs, vc_prev_offset)
    hv_curr, hv_prev = pick(hv_runs, hv_prev_offset)

    result = {"changed": [], "added": [], "removed": []}
    TRACK = ["cpu", "ram_mb", "total_disk_gb", "power_state", "os", "ip_address"]

    def compare(curr_run, prev_run, label):
        if not curr_run or not prev_run: return
        cur.execute("""
            SELECT v.name AS vm_name, v.cpu_count AS cpu, v.memory_mb AS ram_mb,
                   v.total_disk_gb, v.power_state, v.os_name AS os,
                   v.primary_ip AS ip_address
              FROM vms v
              JOIN collection_runs cr ON v.run_id = cr.id
             WHERE cr.legacy_run_id = %s
        """, (curr_run["legacy_id"],))
        curr = {r["vm_name"]: dict(r) for r in cur.fetchall()}
        cur.execute("""
            SELECT v.name AS vm_name, v.cpu_count AS cpu, v.memory_mb AS ram_mb,
                   v.total_disk_gb, v.power_state, v.os_name AS os,
                   v.primary_ip AS ip_address
              FROM vms v
              JOIN collection_runs cr ON v.run_id = cr.id
             WHERE cr.legacy_run_id = %s
        """, (prev_run["legacy_id"],))
        prev = {r["vm_name"]: dict(r) for r in cur.fetchall()}
        for name, c in curr.items():
            if name not in prev:
                result["added"].append({"vm_name": name, "platform": label,
                                        "cpu": c["cpu"], "ram_mb": c["ram_mb"],
                                        "total_disk_gb": float(c["total_disk_gb"] or 0)})
            else:
                diffs = {}
                for f in TRACK:
                    a, b = c.get(f), prev[name].get(f)
                    try: a = float(a) if a is not None else None
                    except (TypeError, ValueError): pass
                    try: b = float(b) if b is not None else None
                    except (TypeError, ValueError): pass
                    if a != b:
                        diffs[f] = {"from": prev[name].get(f), "to": c.get(f)}
                if diffs:
                    result["changed"].append({"vm_name": name, "platform": label,
                                              "changes": diffs})
        for name in prev:
            if name not in curr:
                r = prev[name]
                result["removed"].append({"vm_name": name, "platform": label,
                                          "cpu": r["cpu"], "ram_mb": r["ram_mb"],
                                          "total_disk_gb": float(r["total_disk_gb"] or 0)})

    compare(vc_curr, vc_prev, "VMware")
    compare(hv_curr, hv_prev, "Hyper-V")

    vc_opts = [{"offset": i, "run_id": r["legacy_id"],
                "label": f"Run #{r['legacy_id']} — {str(r['ts'])[:16]}"}
               for i, r in enumerate(vc_runs)]
    hv_opts = [{"offset": i, "run_id": r["legacy_id"],
                "label": f"Run #{r['legacy_id']} — {str(r['ts'])[:16]}"}
               for i, r in enumerate(hv_runs)]

    cur.close(); conn.close()
    return {
        **result,
        "run_info": {
            "vmware_curr": str(vc_curr["ts"])[:16] if vc_curr else None,
            "vmware_prev": str(vc_prev["ts"])[:16] if vc_prev else None,
            "hyperv_curr": str(hv_curr["ts"])[:16] if hv_curr else None,
            "hyperv_prev": str(hv_prev["ts"])[:16] if hv_prev else None,
            "vc_prev_offset": vc_prev_offset, "hv_prev_offset": hv_prev_offset,
        },
        "vc_run_options": vc_opts, "hv_run_options": hv_opts,
    }


@app.route("/api/reporting/changes")
@login_required
def reporting_changes():
    return jsonify(_get_reporting_changes_data(request.args))


@app.route("/api/reporting/changes/export")
@login_required
def export_reporting_changes():
    data = _get_reporting_changes_data(request.args)
    fmt = request.args.get("format", "csv")
    sheets = [
        ("Added", export_utils.rows_with_tb_conversion(
            data["added"], mb_fields=["ram_mb"], gb_fields=["total_disk_gb"]),
         ["vm_name","platform","cpu","ram_tb","total_disk_tb"],
         ["VM Name","Platform","CPU","RAM (TB)","Disk (TB)"]),
        ("Removed", export_utils.rows_with_tb_conversion(
            data["removed"], mb_fields=["ram_mb"], gb_fields=["total_disk_gb"]),
         ["vm_name","platform","cpu","ram_tb","total_disk_tb"],
         ["VM Name","Platform","CPU","RAM (TB)","Disk (TB)"]),
    ]
    return export_utils.build_multi_sheet_export_response(sheets, fmt=fmt,
                                                           base_filename="vm_changes")


@app.route("/api/reporting/vm_analytics")
@login_required
def reporting_vm_analytics():
    conn = get_db_connection(); cur = conn.cursor()
    new_vc, new_hv = _new_run_ids(None, None)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))
    params = list(new_vc) + list(new_hv)

    def q(sql):
        cur.execute(sql, params)
        return cur.fetchall()

    base = f"""
        SELECT v.name AS vm_name, v.memory_mb AS ram_mb, v.cpu_count AS cpu,
               v.total_disk_gb, v.os_name AS os, v.power_state,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform,
               v.primary_ip AS ip_address
          FROM vms v
          JOIN hypervisor_instances hi ON v.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE ((ht.type_key='vmware' AND v.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND v.run_id IN ({hv_ph})))
    """

    top_ram  = q(base + " ORDER BY v.memory_mb DESC LIMIT 10")
    top_disk = q(base + " ORDER BY v.total_disk_gb DESC LIMIT 10")
    top_cpu  = q(base + " ORDER BY v.cpu_count DESC LIMIT 10")

    powered_off = q(base + """ AND v.power_state IN ('poweredOff','Off')
                               AND (v.is_template=0 OR v.is_template IS NULL)
                               ORDER BY v.total_disk_gb DESC""")

    no_ip = q(base + """ AND (v.primary_ip IS NULL OR v.primary_ip = '')
                         AND (v.is_template=0 OR v.is_template IS NULL)
                         ORDER BY platform, vm_name""")

    cur.close(); conn.close()

    def _ser(rows):
        out = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if hasattr(v, "__float__") and not isinstance(v, (int, bool)):
                    d[k] = float(v)
            out.append(d)
        return out

    return jsonify({
        "top_ram": _ser(top_ram), "top_disk": _ser(top_disk), "top_cpu": _ser(top_cpu),
        "powered_off": _ser(powered_off), "no_ip": _ser(no_ip),
        "os_dist": [], "power_dist": [],
        "template_counts": {"templates": 0, "vms": 0},
    })


@app.route("/api/reporting/capacity")
@login_required
def reporting_capacity():
    conn = get_db_connection(); cur = conn.cursor()
    new_vc, new_hv = _new_run_ids(None, None)
    vc_ph = ",".join(["%s"] * len(new_vc))
    hv_ph = ",".join(["%s"] * len(new_hv))
    cur.execute(f"""
        SELECT c.name AS cluster_name, c.cpu_usage_percent, c.memory_usage_percent,
               COALESCE(c.storage_usage_percent,0) AS storage_usage_percent,
               CASE WHEN ht.type_key='vmware' THEN 'VMware' ELSE 'Hyper-V' END AS platform
          FROM clusters c
          JOIN hypervisor_instances hi ON c.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE ((ht.type_key='vmware' AND c.run_id IN ({vc_ph}))
             OR (ht.type_key='hyperv' AND c.run_id IN ({hv_ph})))
           AND (c.cpu_usage_percent > 80 OR c.memory_usage_percent > 80
                OR COALESCE(c.storage_usage_percent,0) > 80)
         ORDER BY c.cpu_usage_percent DESC
    """, list(new_vc) + list(new_hv))
    at_risk = cur.fetchall()
    cur.close(); conn.close()

    def _ser(rows):
        out = []
        for r in rows:
            d = dict(r)
            for k, v in d.items():
                if hasattr(v, "__float__") and not isinstance(v, (int, bool)):
                    d[k] = float(v)
            out.append(d)
        return out

    return jsonify({"at_risk": _ser(at_risk),
                    "disk_growth": {"timestamps": [], "datasets": []},
                    "vm_growth": {"timestamps": [], "datasets": []}})


# ─────────────────────────────────────────────────────────────
#  LIFECYCLE
# ─────────────────────────────────────────────────────────────
@app.route("/lifecycle")
@login_required
def lifecycle_page():
    return render_template("lifecycle.html")


def _get_lifecycle_data(args):
    status = args.get("status", "pending_decommission,restored")
    platform = args.get("platform")
    statuses = [s.strip() for s in status.split(",") if s.strip()]
    conn = get_db_connection(); cur = conn.cursor()
    where = ["vl.status IN (%s)" % ",".join(["%s"] * len(statuses))]
    params = list(statuses)
    if platform:
        where.append("ht.type_key=%s"); params.append(platform)
    cur.execute(f"""
        SELECT vl.id, ht.type_key AS platform, vl.native_id AS vm_key, vl.vm_name,
               hi.name AS context_name, vl.status, vl.first_seen_at, vl.last_seen_at,
               vl.last_seen_run_id, vl.missing_since_run_id, vl.missing_run_count,
               vl.flagged_at, vl.confirmed_by, vl.confirmed_at, vl.notes,
               vl.last_known_cpu, vl.last_known_memory_mb AS last_known_ram_mb,
               vl.last_known_ip
          FROM vm_lifecycle vl
          JOIN hypervisor_instances hi ON vl.hypervisor_instance_id=hi.id
          JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
         WHERE {' AND '.join(where)}
         ORDER BY vl.flagged_at DESC, vl.last_seen_at DESC
    """, params)
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows


@app.route("/api/lifecycle")
@login_required
def api_lifecycle_list():
    rows = _get_lifecycle_data(request.args)
    for r in rows:
        for k in ("first_seen_at", "last_seen_at", "flagged_at", "confirmed_at"):
            if r.get(k): r[k] = r[k].isoformat()
    return jsonify(rows)


@app.route("/api/lifecycle/export")
@login_required
def export_lifecycle():
    rows = _get_lifecycle_data(request.args)
    fmt = request.args.get("format", "csv")
    rows = export_utils.rows_with_tb_conversion(rows, mb_fields=["last_known_ram_mb"])
    columns = ["vm_name","platform","context_name","status","first_seen_at","last_seen_at",
               "last_seen_run_id","missing_since_run_id","missing_run_count","flagged_at",
               "confirmed_by","confirmed_at","notes","last_known_cpu","last_known_ram_tb",
               "last_known_ip","vm_key"]
    return export_utils.build_export_response(rows, fmt=fmt, base_filename="vm_lifecycle",
                                              columns=columns, sheet_name="VM Lifecycle")


@app.route("/api/lifecycle/summary")
@login_required
def api_lifecycle_summary():
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""SELECT status, COUNT(*) AS c FROM vm_lifecycle
                    WHERE status IN ('pending_decommission','restored') GROUP BY status""")
    counts = {r["status"]: r["c"] for r in cur.fetchall()}
    cur.close(); conn.close()
    return jsonify({"pending_decommission": counts.get("pending_decommission", 0),
                    "restored": counts.get("restored", 0)})


@app.route("/api/lifecycle/scan", methods=["POST"])
@login_required
@superadmin_required
def api_lifecycle_scan():
    try:
        return jsonify({"success": True,
                        "result": lifecycle.run_full_scan(actor=session.get("username", "system"))})
    except Exception:
        logger.exception("Manual lifecycle scan failed")
        return jsonify({"success": False, "error": "Scan failed, check server logs."}), 500


@app.route("/api/lifecycle/<int:lifecycle_id>/confirm", methods=["POST"])
@login_required
@superadmin_required
def api_lifecycle_confirm(lifecycle_id):
    notes = (request.json or {}).get("notes", "") if request.is_json else ""
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT status FROM vm_lifecycle WHERE id=%s", (lifecycle_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"success": False, "error": "Not found"}), 404
    if row["status"] not in ("pending_decommission", "restored"):
        cur.close(); conn.close()
        return jsonify({"success": False, "error": f"VM is currently '{row['status']}', not pending."}), 400
    cur.execute("""UPDATE vm_lifecycle SET status='decommissioned', confirmed_by=%s,
                     confirmed_at=NOW(), notes=%s WHERE id=%s""",
                (session.get("username"), notes, lifecycle_id))
    lifecycle._record_event(cur, lifecycle_id, "confirmed_decommission", None,
                            session.get("username"), notes)
    cur.close(); conn.close()
    return jsonify({"success": True})


@app.route("/api/lifecycle/<int:lifecycle_id>/restore", methods=["POST"])
@login_required
@superadmin_required
def api_lifecycle_restore(lifecycle_id):
    notes = (request.json or {}).get("notes", "") if request.is_json else ""
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("SELECT status FROM vm_lifecycle WHERE id=%s", (lifecycle_id,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        return jsonify({"success": False, "error": "Not found"}), 404
    cur.execute("""UPDATE vm_lifecycle SET status='active', missing_since_run_id=NULL,
                     missing_run_count=0, notes=%s WHERE id=%s""", (notes, lifecycle_id))
    lifecycle._record_event(cur, lifecycle_id, "restored", None, session.get("username"),
                            notes or "Manually marked active by admin.")
    cur.close(); conn.close()
    return jsonify({"success": True})


def _start_lifecycle_background_scanner():
    interval = config.LIFECYCLE_SCAN_INTERVAL_MINUTES
    if interval <= 0: return

    def _loop():
        while True:
            time.sleep(interval * 60)
            try: lifecycle.run_full_scan(actor="system")
            except Exception: logger.exception("Background lifecycle scan failed")

    threading.Thread(target=_loop, daemon=True, name="lifecycle-scanner").start()
    logger.info("Lifecycle background scanner started (every %s min)", interval)


_start_lifecycle_background_scanner()


# ─────────────────────────────────────────────────────────────
#  CLI ENTRY
# ─────────────────────────────────────────────────────────────
def _cli_collect_all():
    from collectors.collector_service import collect_all_enabled
    results = collect_all_enabled()
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "collect":
        _cli_collect_all()
    else:
        app.run(host="0.0.0.0", port=5002, debug=config.DEBUG, threaded=True)
