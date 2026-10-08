"""
Adapter registry. Reads hypervisor_types from the DB and exposes a
factory that loads the configured adapter module/class for a given type_key.

Adding a new hypervisor requires only:
  - a row in hypervisor_types (adapter_module + adapter_class set)
  - a module implementing the BaseAdapter contract
No code in app.py, collectors/, or templates/ needs to change.
"""
import importlib
import logging

from .base import BaseAdapter

logger = logging.getLogger("inventory_app.adapters")

_REGISTRY = {}


def register(type_key, adapter_cls):
    _REGISTRY[type_key] = adapter_cls


def load_adapter(type_key, *args, **kwargs):
    """
    Resolve and instantiate an adapter for `type_key`.
    Prefers the registry; falls back to DB-driven dynamic import using
    hypervisor_types.adapter_module / .adapter_class.
    """
    if type_key in _REGISTRY:
        return _REGISTRY[type_key](*args, **kwargs)

    # DB-driven lookup
    from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
    import pymysql
    conn = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                           database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
    try:
        cur = conn.cursor()
        cur.execute("""SELECT adapter_module, adapter_class, adapter_version
                       FROM hypervisor_types WHERE type_key = %s AND enabled = 1""",
                    (type_key,))
        row = cur.fetchone()
        if not row or not row["adapter_module"] or not row["adapter_class"]:
            raise RuntimeError(f"No enabled adapter registered for type_key={type_key!r}")
        mod = importlib.import_module(row["adapter_module"])
        cls = getattr(mod, row["adapter_class"])
        return cls(*args, **kwargs)
    finally:
        conn.close()


# Built-in adapters: register at import time so no DB lookup is needed
# for the two that ship with the app.
try:
    from .vmware.adapter import VMwareAdapter
    from .hyperv.adapter import HypervAdapter
    register("vmware", VMwareAdapter)
    register("hyperv", HypervAdapter)
except Exception as e:  # pragma: no cover - only hit if pyvmomi/etc missing
    logger.warning("Built-in adapters failed to register: %s", e)

__all__ = ["BaseAdapter", "load_adapter", "register"]
