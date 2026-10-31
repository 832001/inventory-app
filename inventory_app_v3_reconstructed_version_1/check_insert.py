# =====================================================================
#  VALIDATION — are ALL runs in the database shown in the dropdown?
#
#  PART 1  (SQL, run it in mysql — no code needed)
#  PART 2  (endpoint, paste into app.py next to dashboard_runs)  ->  /api/debug/runs_check
# =====================================================================

# ---------------------------------------------------------------------
#  PART 1 — SQL.  Replace vcenter_inventory_v3 with your DB name if needed.
# ---------------------------------------------------------------------
SQL_CHECKS = r"""
-- 1) Runs per instance.  "shown_in_dropdown" = what the dropdown can list
--    (instance enabled + not retired + type enabled + run has a start time).
SELECT ht.type_key,
       hi.name                                   AS instance,
       hi.enabled, (hi.deleted_at IS NOT NULL)   AS retired,
       COUNT(*)                                  AS runs_in_db,
       SUM(cr.started_at IS NULL)                AS runs_without_start_time,
       SUM(hi.enabled = 1 AND hi.deleted_at IS NULL AND ht.enabled = 1
           AND cr.started_at IS NOT NULL)        AS shown_in_dropdown,
       MIN(cr.started_at) AS first_run, MAX(cr.started_at) AS last_run
  FROM collection_runs cr
  JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
  JOIN hypervisor_types ht     ON hi.hypervisor_type_id = ht.id
 GROUP BY ht.type_key, hi.name, hi.enabled, hi.deleted_at
 ORDER BY ht.type_key, hi.name;

-- 2) Every proxmox run (expect ONE dropdown line per row when there is one proxmox instance)
SELECT cr.id, hi.name AS instance, cr.started_at, cr.status, cr.legacy_run_id
  FROM collection_runs cr
  JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
  JOIN hypervisor_types ht     ON hi.hypervisor_type_id = ht.id
 WHERE ht.type_key = 'proxmox'
 ORDER BY cr.started_at DESC;

-- 3) The six test runs you just made
SELECT id, hypervisor_instance_id, started_at, status
  FROM collection_runs WHERE id BETWEEN 1124 AND 1129 ORDER BY id;
"""

# ---------------------------------------------------------------------
#  PART 2 — endpoint (superadmin only).  Open in the browser while logged in:
#     /api/debug/runs_check
#     /api/debug/runs_check?ids=1124,1125,1126,1127,1128,1129
# ---------------------------------------------------------------------
@app.route("/api/debug/runs_check")
@login_required
@superadmin_required
def debug_runs_check():
    ids = [int(x) for x in (request.args.get("ids") or "").split(",") if x.strip().isdigit()]
    conn = get_db_connection(); cur = conn.cursor()
    report, found = [], {}

    for t in _live_types(cur):
        key = t["type_key"]
        cur.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(hi.enabled = 1 AND hi.deleted_at IS NULL), 0) AS live,
                   COALESCE(SUM(cr.started_at IS NULL), 0) AS no_start
              FROM collection_runs cr
              JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
              JOIN hypervisor_types ht     ON hi.hypervisor_type_id = ht.id
             WHERE ht.type_key = %s
        """, (key,))
        c = cur.fetchone()

        rows = _type_run_rows(cur, key)              # exactly what the dropdown is built from
        groups = _collections(rows)
        per_inst = {}
        for r in rows:
            per_inst[r["inst"]] = per_inst.get(r["inst"], 0) + 1
        covered = sum(len(g["runs"]) for g in groups)

        for g in groups:
            for inst, rid in g["runs"].items():
                if rid in ids:
                    found[rid] = {"platform": key,
                                  "dropdown_entry": g["start"].strftime("%Y-%m-%d %H:%M:%S"),
                                  "run_id_key": g["key"]}

        report.append({
            "type": key,
            "db_runs_total": int(c["total"]),
            "db_runs_on_live_instances": int(c["live"]),
            "db_runs_without_start_time": int(c["no_start"]),
            "runs_eligible_for_dropdown": len(rows),
            "dropdown_entries": len(groups),
            "runs_covered_by_entries": covered,
            "runs_lost": len(rows) - covered,                         # must be 0
            "most_runs_of_one_instance": max(per_inst.values()) if per_inst else 0,
            "runs_per_instance_id": per_inst,
            "OK": covered == len(rows) and len(groups) >= (max(per_inst.values()) if per_inst else 0),
            "note": ("single instance: entries must equal runs" if len(per_inst) == 1 else
                     "several instances: runs of different instances in one collection share an entry"),
        })

    missing = [i for i in ids if i not in found]
    why = {}
    for i in missing:
        cur.execute("""
            SELECT cr.id, ht.type_key, cr.started_at, hi.enabled, hi.deleted_at, ht.enabled AS type_enabled
              FROM collection_runs cr
              JOIN hypervisor_instances hi ON cr.hypervisor_instance_id = hi.id
              JOIN hypervisor_types ht     ON hi.hypervisor_type_id = ht.id
             WHERE cr.id = %s
        """, (i,))
        r = cur.fetchone()
        if not r:
            why[i] = "no such collection_runs.id"
        elif r["started_at"] is None:
            why[i] = "run has no started_at"
        elif not r["enabled"] or r["deleted_at"] or not r["type_enabled"]:
            why[i] = "instance or type is disabled/retired"
        else:
            why[i] = "unknown - send me this row"
    cur.close(); conn.close()
    return jsonify({"types": report, "ids_found": found, "ids_missing": why})
