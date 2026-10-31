import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
DEBUG = os.getenv("FLASK_DEBUG", "false").strip().lower() in ("1", "true", "yes", "on")

DB_HOST = os.getenv("DB_HOST", "10.19.152.234")
DB_USER = os.getenv("DB_USER", "inventory_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "vcenter_inventory_v3")

LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://Cairo.TelecomEgypt.corp")
LDAP_REALM = os.getenv("LDAP_REALM", "Cairo.TelecomEgypt.corp")

PLAYBOOK_CREATE_VM_VMWARE = os.getenv(
    "PLAYBOOK_CREATE_VM_VMWARE", "/root/project/playbooks/create_vm_vmware.yml"
)
PLAYBOOK_CREATE_VM_HYPERV = os.getenv(
    "PLAYBOOK_CREATE_VM_HYPERV", "/root/project/playbooks/create_vm_hyperv.yml"
)
ANSIBLE_TMP_DIR = os.getenv("ANSIBLE_TMP_DIR", "/root/project/tmp_vars")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

MODEL_DIR = os.getenv("MODEL_DIR", str(BASE_DIR / "models"))
DECOMMISSION_GRACE_RUNS = int(os.getenv("DECOMMISSION_GRACE_RUNS", "3"))
LIFECYCLE_SCAN_INTERVAL_MINUTES = int(os.getenv("LIFECYCLE_SCAN_INTERVAL_MINUTES", "15"))


# ── Document Analyst ────────────────────────────────────────
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
DOCS_MAX_MB = int(os.environ.get("DOCS_MAX_MB", "50"))          # per-file cap
DOCS_CONTEXT_CHARS = int(os.environ.get("DOCS_CONTEXT_CHARS", "24000"))
QWEN_MODEL = os.environ.get("QWEN_MODEL", "qwen3-14b-local:latest")


CREDENTIAL_MASTER_KEY = os.environ.get("CREDENTIAL_MASTER_KEY")
