#!/usr/bin/env python3
"""
test_import.py — Standalone test runner for adapters and collector.
Usage:
    python3 test_import.py vmware
    python3 test_import.py proxmox
    python3 test_import.py all
"""
import sys
import logging
import pymysql
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
from collectors.collector_service import collect_instance

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def get_db():
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                           database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_import.py [vmware|proxmox|all]")
        sys.exit(1)

    target = sys.argv[1].lower()
    conn = get_db()
    cur = conn.cursor()

    # Find instances to test
    if target == 'all':
        cur.execute("""
            SELECT hi.id, hi.name, ht.type_key 
            FROM hypervisor_instances hi
            JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
            WHERE hi.enabled = 1 AND hi.deleted_at IS NULL
        """)
    else:
        cur.execute("""
            SELECT hi.id, hi.name, ht.type_key 
            FROM hypervisor_instances hi
            JOIN hypervisor_types ht ON hi.hypervisor_type_id = ht.id
            WHERE ht.type_key = %s AND hi.enabled = 1 AND hi.deleted_at IS NULL
        """, (target,))

    instances = cur.fetchall()
    cur.close()
    conn.close()

    if not instances:
        print(f"❌ No active instances found for type: {target}")
        sys.exit(1)

    print(f"\n🚀 Starting test collection for {len(instances)} instance(s)...\n")

    for inst in instances:
        print(f"▶ Testing instance: {inst['name']} ({inst['type_key']}) [ID: {inst['id']}]")
        try:
            result = collect_instance(inst['id'])
            print(f"  ✅ Status: {result['status']}")
            print(f"     Run ID: {result['run_id']}")
            print(f"     Inserted -> Clusters: {result.get('clusters', 0)} | "
                  f"Hosts: {result.get('hosts', 0)} | "
                  f"Datastores: {result.get('datastores', 0)} | "
                  f"VMs: {result.get('vms', 0)} | "
                  f"Disks: {result.get('disks', 0)}")
        except Exception as e:
            print(f"  ❌ Failed: {e}")
        print("-" * 50)

if __name__ == "__main__":
    main()
