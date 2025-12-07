"""
Improved Queue Control
----------------------
This version identifies each "active user" using:

    unique_id = ip + user_agent

So multiple curl/browser hits from localhost count as different users.

- Tracks active unique clients in Redis SET
- Enforces MAX_ACTIVE_CLIENTS limit
- Provides global slowdown support
"""

from ..state import (
    rdb,
    ACTIVE_TTL,
    MAX_ACTIVE_CLIENTS,
    HOST_IP,
    GLOBAL_SLOWDOWN_SECONDS,
)
from ..utils import log_console

# Redis keys
ACTIVE_SET = "sec:active:ips"
GLOBAL_SLOWDOWN_KEY = "sec:slowdown"


# -------------------------------------------------------
# Generate unique per-user identifier
# -------------------------------------------------------
def _make_unique(ip: str, ua: str) -> str:
    ua = ua or "unknown"
    ua = ua.replace(" ", "_")[:80]  # sanitize
    return f"{ip}:{ua}"


# -------------------------------------------------------
# Active user tracking
# -------------------------------------------------------
def mark_active(ip: str, ua: str = ""):
    """
    Store (ip + user-agent) as unique user in Redis SET.
    Auto-cleans with TTL.
    """
    unique = _make_unique(ip, ua)

    try:
        pipe = rdb.pipeline()
        pipe.sadd(ACTIVE_SET, unique)
        pipe.expire(ACTIVE_SET, ACTIVE_TTL)
        pipe.execute()
    except Exception:
        pass


def unmark_active(ip: str, ua: str = ""):
    """Remove specific unique user."""
    unique = _make_unique(ip, ua)
    try:
        rdb.srem(ACTIVE_SET, unique)
    except Exception:
        pass


def get_active_count() -> int:
    """
    Returns number of unique users.
    """
    try:
        return int(rdb.scard(ACTIVE_SET) or 0)
    except Exception:
        return 0


def allowed_to_enter(ip: str, ua: str = "") -> bool:
    """
    Check if request should pass queue.

    - HOST_IP always bypasses
    - If under the limit, add user and allow
    - Else return False (caller shows wait page)
    """
    if ip == HOST_IP:
        return True

    try:
        active = get_active_count()
        if active < MAX_ACTIVE_CLIENTS:
            mark_active(ip, ua)
            return True

        log_console(ip, f"[Queue] Rejected — too many active clients ({active})")
        return False

    except Exception:
        # Fail-open on Redis issues
        return True


# -------------------------------------------------------
# Global slowdown (optional throttling)
# -------------------------------------------------------
def set_global_slowdown(seconds: int = None):
    ttl = GLOBAL_SLOWDOWN_SECONDS if seconds is None else int(seconds)
    try:
        rdb.setex(GLOBAL_SLOWDOWN_KEY, ttl, "1")
    except Exception:
        pass


def clear_global_slowdown():
    try:
        rdb.delete(GLOBAL_SLOWDOWN_KEY)
    except Exception:
        pass


def is_global_slowdown() -> bool:
    try:
        return bool(rdb.exists(GLOBAL_SLOWDOWN_KEY))
    except Exception:
        return False
