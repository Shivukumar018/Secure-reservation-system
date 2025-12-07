# security/protections/brute_force.py
"""
Brute-force protection helpers.

Behavior:
 - Maintain short-window counters for username and IP.
 - When username reaches BF_MAX_FAILS_USER -> lock user for BF_USER_LOCK_SECONDS,
   also apply IP block and set human-readable reason keys.
 - When IP reaches BF_MAX_FAILS_IP -> lock IP for BF_IP_BLOCK_SECONDS and set reason key.
 - If IP reaches half the IP threshold, apply a short temporary penalty to slow attackers.
 - Companion reason keys:
     sec:block:reason:ip:<ip>        -> "bruteforce"
     sec:block:reason:ip:<ip>:temp   -> "bruteforce_temp"
     sec:block:reason:user:<user>    -> "bruteforce"
"""

from ..state import rdb, BF_MAX_FAILS_USER, BF_USER_LOCK_SECONDS, BF_MAX_FAILS_IP, BF_IP_BLOCK_SECONDS

USER_FAIL = "sec:fail:user:"
IP_FAIL = "sec:fail:ip:"
USER_BLOCK = "sec:block:user:"
IP_BLOCK = "sec:block:ip:"
IP_BLOCK_REASON = "sec:block:reason:ip:"        # companion key for human-readable reason
USER_BLOCK_REASON = "sec:block:reason:user:"    # optional user reason key

# Lua script: increment fail key, set expire and set block when limit reached
# Returns current counter (may be >= limit when block triggered)
SCRIPT = """
local fail_key = KEYS[1]
local block_key = KEYS[2]
local limit = tonumber(ARGV[1])
local fail_window = tonumber(ARGV[2])
local block_ttl = tonumber(ARGV[3])
local cnt = redis.call('incr', fail_key)
if cnt == 1 then redis.call('expire', fail_key, fail_window) end
if cnt >= limit then
  redis.call('setex', block_key, block_ttl, '1')
  redis.call('del', fail_key)
  return cnt
end
return cnt
"""

# Short fail window for counting attempts (seconds)
FAIL_WINDOW = 900  # 15 minutes

# Short temporary IP penalty we apply when IP fails reach half the IP limit (tunable)
HALF_IP_PENALTY_SECONDS = 300  # 5 minutes


def incr_fail_counters(username: str, ip: str):
    """
    Increment fail counters for username and IP. Return tuple:
      (blocked_user: bool, blocked_ip: bool, reason_str: str)

    Notes:
      - When username reaches BF_MAX_FAILS_USER: set user lock + full IP lock + companion reason keys.
      - When IP fail count reaches half threshold: set short penalty to slow automated attacks.
      - When IP reaches BF_MAX_FAILS_IP: set full IP lock + reason.
    """
    blocked_user = False
    blocked_ip = False
    reasons = []

    # 1) Handle username-based failures (atomic via SCRIPT)
    if username:
        try:
            ucnt = rdb.eval(SCRIPT, 2,
                            f"{USER_FAIL}{username}", f"{USER_BLOCK}{username}",
                            BF_MAX_FAILS_USER, FAIL_WINDOW, BF_USER_LOCK_SECONDS)
            try:
                ucnt = int(ucnt)
            except Exception:
                ucnt = 0
            if ucnt >= BF_MAX_FAILS_USER:
                # user lock was triggered by script; mark user and also apply IP-level block + reason
                blocked_user = True
                reasons.append("user_locked")
                try:
                    rdb.setex(f"{IP_BLOCK}{ip}", BF_IP_BLOCK_SECONDS, "1")
                    rdb.setex(f"{IP_BLOCK_REASON}{ip}", BF_IP_BLOCK_SECONDS, "bruteforce")
                    rdb.setex(f"{USER_BLOCK_REASON}{username}", BF_USER_LOCK_SECONDS, "bruteforce")
                    blocked_ip = True
                    reasons.append("ip_block_by_user_lock")
                except Exception:
                    # best-effort; ignore Redis errors here
                    pass
        except Exception:
            # fail-open: if Redis errors, do not block here
            pass

    # 2) Handle IP fail counting & progressive action
    try:
        icnt = rdb.eval(SCRIPT, 2,
                        f"{IP_FAIL}{ip}", f"{IP_BLOCK}{ip}",
                        BF_MAX_FAILS_IP, FAIL_WINDOW, BF_IP_BLOCK_SECONDS)
        try:
            icnt = int(icnt)
        except Exception:
            icnt = 0

        # If the IP fail count reaches half the threshold, set a short penalty to slow attacker
        half_threshold = max(1, BF_MAX_FAILS_IP // 2)
        if icnt >= half_threshold and icnt < BF_MAX_FAILS_IP:
            # best-effort: set a short temporary penalty key
            try:
                rdb.setex(f"{IP_BLOCK}{ip}:temp", HALF_IP_PENALTY_SECONDS, "1")
                # set companion reason for this temp block
                rdb.setex(f"{IP_BLOCK_REASON}{ip}:temp", HALF_IP_PENALTY_SECONDS, "bruteforce_temp")
                reasons.append("ip_temp_penalty")
            except Exception:
                pass

        # If ip reached limit, script sets IP_BLOCK; ensure companion reason present
        if icnt >= BF_MAX_FAILS_IP:
            blocked_ip = True
            reasons.append("ip_blocked")
            try:
                rdb.setex(f"{IP_BLOCK_REASON}{ip}", BF_IP_BLOCK_SECONDS, "bruteforce")
            except Exception:
                pass
    except Exception:
        # ignore Redis failures for counting
        pass

    return blocked_user, blocked_ip, ";".join(reasons)


def reset_fail_counters(username: str, ip: str):
    """
    Clear failure counters and companion reason keys for username and IP.
    """
    try:
        if username:
            rdb.delete(f"{USER_FAIL}{username}")
    except Exception:
        pass
    try:
        rdb.delete(f"{IP_FAIL}{ip}")
    except Exception:
        pass
    # also clear any companion reason keys if present
    try:
        rdb.delete(f"{IP_BLOCK_REASON}{ip}")
        rdb.delete(f"{IP_BLOCK_REASON}{ip}:temp")
    except Exception:
        pass
    try:
        if username:
            rdb.delete(f"{USER_BLOCK_REASON}{username}")
    except Exception:
        pass


def is_user_blocked(username: str):
    """
    Return TTL (seconds) if user is blocked, otherwise None.
    """
    try:
        if not username:
            return None
        ttl = rdb.ttl(f"{USER_BLOCK}{username}")
        return ttl if ttl and int(ttl) > 0 else None
    except Exception:
        return None


def is_ip_blocked(ip: str):
    """
    Return TTL (seconds) if IP is blocked (main block or temporary), otherwise None.
    Checks both permanent and temp keys.
    """
    try:
        ttl_main = rdb.ttl(f"{IP_BLOCK}{ip}")
        if ttl_main and int(ttl_main) > 0:
            return ttl_main
        # check temporary key
        ttl_temp = rdb.ttl(f"{IP_BLOCK}{ip}:temp")
        return ttl_temp if ttl_temp and int(ttl_temp) > 0 else None
    except Exception:
        return None
