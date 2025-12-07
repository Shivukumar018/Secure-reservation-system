import os
import redis
from datetime import datetime
import zoneinfo

# ========================
#   Core Configuration
# ========================
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:5000").strip()
PROXY_PORT = int(os.getenv("PROXY_PORT", "8000").strip())

# Toggles
PROTECTION_ON = os.getenv("PROTECTION_ON", "true").lower().strip() == "true"
TRUST_XFF = os.getenv("TRUST_XFF", "false").lower().strip() == "true"

# ========================
#   Secrets (Required)
# ========================
INTERNAL_SECRET = os.getenv("INTERNAL_SECRET", "Shivu_Internal_Proxy_Secret_12345").strip()
SESSION_SECRET = os.getenv("SESSION_SECRET", "ShivuSessionSecret98765").strip()
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "ShivuSecureAdminToken123").strip()

# ========================
#   Redis Configuration
# ========================
REDIS_HOST = os.getenv("REDIS_HOST", "localhost").strip()
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379").strip())
REDIS_DB = int(os.getenv("REDIS_DB", "0").strip())

rdb = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
    socket_timeout=2,
    socket_connect_timeout=2,
    retry_on_timeout=True,
    health_check_interval=30,
)

# ========================
#   Limits & Thresholds
# ========================
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "9").strip())
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "15").strip())
PENALTY_SECONDS = int(os.getenv("PENALTY_SECONDS", "150").strip())

MAX_ACTIVE_CLIENTS = int(os.getenv("MAX_ACTIVE_CLIENTS", "100").strip())
ACTIVE_TTL = int(os.getenv("ACTIVE_TTL", "60").strip())
HOST_IP = os.getenv("HOST_IP", "0.0.0.0").strip()

BF_MAX_FAILS_USER = int(os.getenv("BF_MAX_FAILS_USER", "4").strip())
BF_USER_LOCK_SECONDS = int(os.getenv("BF_USER_LOCK_SECONDS", "7200").strip())
BF_MAX_FAILS_IP = int(os.getenv("BF_MAX_FAILS_IP", "20").strip())
BF_IP_BLOCK_SECONDS = int(os.getenv("BF_IP_BLOCK_SECONDS", "7200").strip())

UNPROT_CONC_THRESHOLD = int(os.getenv("UNPROT_CONC_THRESHOLD", "4").strip())
GLOBAL_SLOWDOWN_SECONDS = int(os.getenv("GLOBAL_SLOWDOWN_SECONDS", "20").strip())
SLOWDOWN_DELAY = int(os.getenv("SLOWDOWN_DELAY", "0").strip())

# ========================
#   Database & Logging
# ========================
DB_FILE = os.path.join(os.path.dirname(__file__), "security_logs.db")
IST = zoneinfo.ZoneInfo("Asia/Kolkata")

# Safety caps
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(64 * 1024)).strip())  # 64 KB default

# ========================
#   Helpers
# ========================
def ist_now() -> str:
    """Returns current IST timestamp formatted for logs."""
    return datetime.now(IST).strftime("%d %b %Y, %I:%M:%S %p")
