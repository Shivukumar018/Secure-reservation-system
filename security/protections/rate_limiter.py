# security/protections/rate_limiter.py
"""
Enhanced rate limiter module.

Purpose:
 - Limit request bursts per IP to prevent abuse.
 - Apply temporary penalties when limits are exceeded.
 - Integrate cleanly with Redis atomic Lua scripts for high accuracy.
"""

from ..state import rdb, RATE_LIMIT, WINDOW_SECONDS, PENALTY_SECONDS, MAX_BODY_BYTES

RATE_KEY = "sec:rate:"
PENALTY_KEY = "sec:penalty:"
REASON_KEY = "sec:penalty:reason:"  # companion reason for blocked IPs

# Lua: incr + expire + optional setex penalty
RATE_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local penalty_key = ARGV[3]
local penalty = tonumber(ARGV[4])
local reason_key = ARGV[5]
local v = redis.call('incr', key)
if v == 1 then redis.call('expire', key, window) end
if v > limit then
  redis.call('setex', penalty_key, penalty, '1')
  redis.call('setex', reason_key, penalty, 'rate_limit_exceeded')
  return 0
end
return v
"""


def record_rate(ip: str):
    """
    Increment rate counter for an IP.
    Returns (allowed: bool, reason: str)
    - False if rate limit exceeded (penalty active)
    - True otherwise
    """
    rate_key = f"{RATE_KEY}{ip}"
    penalty_key = f"{PENALTY_KEY}{ip}"
    reason_key = f"{REASON_KEY}{ip}"
    try:
        res = rdb.eval(RATE_SCRIPT, 1, rate_key, RATE_LIMIT, WINDOW_SECONDS, penalty_key, PENALTY_SECONDS, reason_key)
        if res == 0:
            return False, f"Exceeded {RATE_LIMIT}/{WINDOW_SECONDS}s"
        return True, ""
    except Exception as e:
        # fail-open but flag reason for logs
        return True, f"redis_err:{e}"


def penalty_ttl(ip: str):
    """Return TTL (seconds) if an IP penalty is active, else None."""
    try:
        ttl = rdb.ttl(f"{PENALTY_KEY}{ip}")
        return ttl if ttl and int(ttl) > 0 else None
    except Exception:
        return None


def get_penalty_reason(ip: str) -> str:
    """Return stored reason for a rate-limit penalty."""
    try:
        reason = rdb.get(f"{REASON_KEY}{ip}")
        return reason or ""
    except Exception:
        return ""
