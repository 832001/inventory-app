"""VM lifecycle/decommission tracking for inventory_app_v3.

Reconstructed from the lifecycle API contract used by app.py and the
normalized schema described in the supplied migration artifact.
"""
import logging
import pymysql
import config

logger = logging.getLogger("inventory_app.lifecycle")

def _db():
    return pymysql.connect(
        host=config.DB_HOST, user=config.DB_USER, password=config.DB_PASSWORD,
        database=config.DB_NAME, cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )

def _record_event(cursor, lifecycle_id, event_type, run_id=None, actor=None, notes=None):
    cursor.execute(
        """INSERT INTO vm_lifecycle_events
           (lifecycle_id, event_type, run_id, actor, notes, created_at)
           VALUES (%s,%s,%s,%s,%s,NOW())""",
        (lifecycle_id, event_type, run_id, actor, notes),
    )

def run_full_scan(actor="system"):
    conn = _db()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT v.id, v.hypervisor_instance_id, v.native_id, v.name,
                   v.cpu_count, v.memory_mb, v.primary_ip,
                   v.run_id, cr.legacy_run_id, ht.type_key
              FROM vms v
              JOIN collection_runs cr ON v.run_id=cr.id
              JOIN hypervisor_instances hi ON v.hypervisor_instance_id=hi.id
              JOIN hypervisor_types ht ON hi.hypervisor_type_id=ht.id
             WHERE cr.status='success'
               AND v.run_id IN (
                   SELECT MAX(cr2.id)
                     FROM collection_runs cr2
                    WHERE cr2.hypervisor_instance_id=v.hypervisor_instance_id
                      AND cr2.status='success'
               )
        """)
        current = cur.fetchall()
        seen = {
            (r["hypervisor_instance_id"], r["native_id"]): r
            for r in current
        }

        for key, v in seen.items():
            cur.execute("""
                SELECT id, status FROM vm_lifecycle
                 WHERE hypervisor_instance_id=%s AND native_id=%s
                 ORDER BY id DESC LIMIT 1
            """, key)
            existing = cur.fetchone()
            if existing:
                cur.execute("""
                    UPDATE vm_lifecycle
                       SET vm_name=%s, last_seen_at=NOW(), last_seen_run_id=%s,
                           missing_since_run_id=NULL, missing_run_count=0,
                           status=CASE WHEN status='decommissioned'
                                       THEN status ELSE 'active' END,
                           last_known_cpu=%s, last_known_memory_mb=%s,
                           last_known_ip=%s
                     WHERE id=%s
                """, (v["name"], v["run_id"], v.get("cpu_count"),
                       v.get("memory_mb"), v.get("primary_ip"), existing["id"]))
            else:
                cur.execute("""
                    INSERT INTO vm_lifecycle
                      (hypervisor_instance_id, native_id, vm_name, status,
                       first_seen_at, last_seen_at, last_seen_run_id,
                       missing_run_count, last_known_cpu, last_known_memory_mb,
                       last_known_ip)
                    VALUES (%s,%s,%s,'active',NOW(),NOW(),%s,0,%s,%s,%s)
                """, (v["hypervisor_instance_id"], v["native_id"], v["name"],
                       v["run_id"], v.get("cpu_count"), v.get("memory_mb"),
                       v.get("primary_ip")))

        # Increment missing counters for lifecycle records not present in
        # the latest successful snapshot for their instance.
        cur.execute("SELECT id, hypervisor_instance_id, native_id, status, missing_run_count FROM vm_lifecycle WHERE status <> 'decommissioned'")
        records = cur.fetchall()
        for r in records:
            if (r["hypervisor_instance_id"], r["native_id"]) not in seen:
                new_count = int(r.get("missing_run_count") or 0) + 1
                cur.execute("""
                    UPDATE vm_lifecycle
                       SET missing_run_count=%s,
                           missing_since_run_id=COALESCE(missing_since_run_id, NULL),
                           flagged_at=CASE WHEN %s >= %s AND flagged_at IS NULL THEN NOW() ELSE flagged_at END,
                           status=CASE WHEN %s >= %s THEN 'pending_decommission' ELSE status END
                     WHERE id=%s
                """, (new_count, new_count, config.DECOMMISSION_GRACE_RUNS,
                       new_count, config.DECOMMISSION_GRACE_RUNS, r["id"]))
        conn.commit()
        return {"success": True, "current_vms": len(current), "scanned": len(records)}
    except Exception:
        conn.rollback()
        logger.exception("Lifecycle scan failed")
        raise
    finally:
        conn.close()
