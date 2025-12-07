# security/proxy.py
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import Response, JSONResponse
from security.protections.xss_detector import is_xss

import httpx
import asyncio
import logging
import sqlite3
from contextlib import asynccontextmanager
from typing import List

from security.state import (
    BACKEND_URL, PROXY_PORT, PROTECTION_ON, TRUST_XFF, ADMIN_TOKEN,
    DB_FILE, BF_IP_BLOCK_SECONDS, BF_USER_LOCK_SECONDS, rdb,
    ist_now, MAX_BODY_BYTES, INTERNAL_SECRET,
    BF_MAX_FAILS_IP
)
from security.utils import (
    log_console, render_wait_page, render_timed_block_page,
    render_backend_error, build_forward_headers
)
from security.logs.sqlite_logger import init_db, write_log, write_ml_log
from security.protections.rate_limiter import record_rate, penalty_ttl
from security.protections.brute_force import (
    incr_fail_counters, reset_fail_counters, is_user_blocked, is_ip_blocked
)
from security.protections.queue_control import (
    allowed_to_enter, mark_active, set_global_slowdown, is_global_slowdown
)
from security.protections.sqli_detector import is_sqli
from security.protections.ml_detector import ml_predict_and_log  # optional, if present

# -------------------------
# Lifespan / app init
# -------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # initialize DB (sqlite)
    try:
        maybe = init_db()
        if asyncio.iscoroutine(maybe):
            await maybe
    except Exception:
        pass

    # http client used to forward requests
    app.state.http = httpx.AsyncClient(timeout=20.0)
    # protection flag (mutable at runtime) - default to configured PROTECTION_ON
    app.state.protection = bool(PROTECTION_ON)
    yield
    try:
        await app.state.http.aclose()
    except Exception:
        pass

app = FastAPI(title="Golden Express Proxy — Modular", lifespan=lifespan)

# quiet exception handler for loop
asyncio.get_event_loop().set_exception_handler(
    lambda loop, ctx: logging.debug(ctx.get("message"))
)

# -------------------------
# Admin helper
# -------------------------
def require_admin(request: Request):
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=500, detail="ADMIN_TOKEN not configured.")
    auth = request.headers.get("authorization", "")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing admin token.")
    token = auth.split(" ", 1)[1].strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin token.")

# -------------------------
# Health endpoint
# -------------------------
@app.get("/health")
async def health(request: Request):
    return {"status": "ok", "protection": "on" if request.app.state.protection else "off"}

# -------------------------
# Admin endpoints
# -------------------------
@app.post("/admin/login")
async def admin_login(request: Request):
    form = await request.form()
    token = form.get("token")
    if token == ADMIN_TOKEN:
        return {"detail": "login_success"}
    return {"detail": "invalid_credentials"}

from .protections.queue_control import ACTIVE_SET
from .state import rdb

@app.get("/admin/status")
async def admin_status(request: Request):
    """Returns system protection mode, slowdown status, and live active user count."""
    try:
        active_users = 0
        if rdb.exists(ACTIVE_SET):
            active_users = rdb.scard(ACTIVE_SET) or 0
    except Exception:
        active_users = -1  # Redis down or unreachable

    return {
        
    "mode": "STRICT" if request.app.state.protection else "RAW",
    "active_users": active_users
    }

@app.post("/admin/mode")
async def admin_mode(request: Request, mode: str = None, _: None = Depends(require_admin)):
    """
    POST /admin/mode with form/body param 'mode' = "strict" or "raw"
    STRICT = protections active
    RAW = protections disabled (no logging)
    """
    mode_val = None
    # accept form or query param or json
    try:
        form = await request.form()
        if not mode:
            mode = form.get("mode")
    except Exception:
        pass
    if not mode:
        params = dict(request.query_params)
        mode = params.get("mode") or mode

    if not mode:
        return JSONResponse({"error": "missing mode param, use 'strict' or 'raw'."}, status_code=400)

    m = mode.strip().lower()
    if m not in ("strict", "raw"):
        return JSONResponse({"error": "invalid mode; use 'strict' or 'raw'."}, status_code=400)

    request.app.state.protection = (m == "strict")
    return {"detail": "ok", "mode": "STRICT" if request.app.state.protection else "RAW"}

@app.get("/admin/logs")
def admin_logs(limit: int = 500, _: None = Depends(require_admin), request: Request = None):
    """
    Return sqlite logs only when protection is strict.
    When in RAW mode this endpoint returns an empty list (no logging).
    """
    if not request.app.state.protection:
        return {"logs": []}
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute(
            "SELECT ts, client_ip, identifier, path, method, outcome, reason "
            "FROM logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return {
            "logs": [
                {
                    "ts": r[0],
                    "client_ip": r[1],
                    "identifier": r[2],
                    "path": r[3],
                    "method": r[4],
                    "outcome": r[5],
                    "reason": r[6],
                }
                for r in rows
            ]
        }
    except Exception as e:
        return {"logs": [], "error": str(e)}

@app.get("/admin/ml_logs")
def admin_ml_logs(limit: int = 500, _: None = Depends(require_admin), request: Request = None):
    """Return ML logs, only when strict mode (no logging in RAW)."""
    if not request.app.state.protection:
        return {"logs": []}
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        cur = conn.cursor()
        cur.execute(
            "SELECT ts, client_ip, path, score, reason FROM ml_logs ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return {
            "logs": [
                {"ts": r[0], "client_ip": r[1], "path": r[2], "score": r[3], "reason": r[4]} for r in rows
            ]
        }
    except Exception as e:
        return {"logs": [], "error": str(e)}


@app.get("/admin/blocked_ips")
def admin_blocked_ips(_: None = Depends(require_admin)):
    """
    Return list of blocked ip keys and TTLs and reason keys. Uses the same "sec:block:ip:" keys.
    """
    try:
        keys = rdb.keys("sec:block:ip:*")
        result = []
        for k in keys:
            # key format: sec:block:ip:<ip> or sec:block:ip:<ip>:temp
            ip = k.split(":", 3)[-1]
            ttl = rdb.ttl(k) or -1
            # companion reason key (exact match, prefer non-temp)
            reason = rdb.get(f"sec:block:reason:ip:{ip}") or rdb.get(f"sec:block:reason:ip:{ip}:temp") or ""
            result.append({"key": k, "ip": ip, "ttl": int(ttl), "reason": reason})
        return {"blocked": result}
    except Exception as e:
        return {"blocked": [], "error": str(e)}
from fastapi import Form

@app.post("/admin/unblock")
def admin_unblock(ip: str = Form(...), _: None = Depends(require_admin)):
    """
    POST body or query 'ip' to remove block keys and companion reason/fail keys.
    Example: POST /admin/unblock?ip=1.2.3.4
    """
    if not ip:
        return JSONResponse({"error": "missing ip param"}, status_code=400)
    try:
        # primary keys
        rdb.delete(f"sec:block:ip:{ip}")
        rdb.delete(f"sec:block:ip:{ip}:temp")
        rdb.delete(f"sec:block:reason:ip:{ip}")
        rdb.delete(f"sec:block:reason:ip:{ip}:temp")
        # clear fail counters and related
        rdb.delete(f"sec:fail:ip:{ip}")
        # remove from active set (if present)
        rdb.srem("sec:active:ips", ip)
        return {"detail": "unblocked", "ip": ip}
    except Exception as e:
        return {"error": str(e)}

@app.get("/admin/active_ips")
def admin_active_ips(_: None = Depends(require_admin)):
    try:
        members = list(rdb.smembers("sec:active:ips") or [])
        return {"active": members}
    except Exception as e:
        return {"active": [], "error": str(e)}
# -------------------------
# Main proxy middleware
# -------------------------
@app.middleware("http")
async def guard_and_proxy(request: Request, call_next):
    path, method = request.url.path, request.method

    # allow admin and health endpoints directly through FastAPI stack
    if path.startswith("/admin") or path == "/health":
        return await call_next(request)

    # identify client IP (respect TRUST_XFF setting)
    if TRUST_XFF:
        xf = request.headers.get("x-forwarded-for")
        ip = xf.split(",")[0].strip() if xf else (request.client.host or "unknown")
    else:
        ip = request.client.host or "unknown"

    ua = (request.headers.get("user-agent", "unknown") or "unknown")[:200]
    identifier = f"{ip}:{ua}"

    # read body (with size cap)
    try:
        raw_body = await request.body()
        if raw_body and len(raw_body) > MAX_BODY_BYTES:
            if request.app.state.protection:
                await write_log(ip, identifier, path, method, "blocked", "body_too_large")
            return render_timed_block_page(
                "Request Too Large", "Payload exceeds allowed size.", 0, "body_too_large", status_code=413
            )
    except Exception:
        raw_body = b""

    body_text = raw_body.decode(errors="ignore") if raw_body else ""

    # attempt to extract username for brute-force tracking
    username = None
    try:
        for k in ("username", "user", "email", "identifier", "phone"):
            if k in request.query_params:
                username = request.query_params.get(k)
                break
        if not username and body_text:
            import urllib.parse, json
            parsed = urllib.parse.parse_qs(body_text)
            for k in ("username", "user", "email", "identifier", "phone"):
                if k in parsed:
                    username = parsed[k][0]
                    break

            if not username:
                try:
                    j = json.loads(body_text)
                    for k in ("username", "user", "email", "identifier", "phone"):
                        if k in j:
                            v = j.get(k)
                            username = v[0] if isinstance(v, (list, tuple)) else v
                            break
                except Exception:
                    pass
    except Exception:
        username = None

    # If protection is OFF (RAW mode)
    if not request.app.state.protection:
        try:
            resp = await app.state.http.request(
                method,
                BACKEND_URL + path,
                params=request.query_params,
                content=raw_body,
                headers=build_forward_headers(request, ip),
            )
            skip_headers = {
                "connection", "keep-alive", "transfer-encoding", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "upgrade", "content-encoding",
            }
            sanitized = {k: v for k, v in resp.headers.items() if k.lower() not in skip_headers}
            return Response(content=resp.content, status_code=resp.status_code, headers=sanitized)

        except Exception as e:
            await write_log(ip, identifier, path, method, "backend_unreachable", str(e))
            return render_backend_error()

    # protection ON
    await write_log(ip, identifier, path, method, "received", "")

    # Early firewall check
    ip_ttl = is_ip_blocked(ip)
    if ip_ttl and int(ip_ttl) > 0:
        try:
            block_reason = rdb.get(f"sec:block:reason:ip:{ip}") or "ip_locked"
        except Exception:
            block_reason = "ip_locked"

        await write_log(ip, identifier, path, method, "blocked_by_firewall", f"{block_reason}_early")

        return render_timed_block_page(
            "IP Blocked",
            "Your IP has been temporarily blocked.",
            ip_ttl,
            str(block_reason),
            status_code=403,
        )

    # -------------------------
    # SQLi detection BEFORE forwarding
    # -------------------------
    try:
        scope = request.scope

        raw_path = scope.get("raw_path", b"").decode(errors="ignore")
        raw_query = scope.get("query_string", b"").decode(errors="ignore")

        raw_url = raw_path + ("?" + raw_query if raw_query else "")
        combined_payload = f"{raw_url} {ua} {body_text}"

        sqli_flag, sqli_score, sqli_reason = is_sqli(combined_payload)

    except Exception as e:
        await write_log(ip, identifier, path, method, "sqli_detector_error", str(e))
        sqli_flag, sqli_score, sqli_reason = True, 1.0, f"detector_error:{e}"

    # -------------------------
    # SQLi BLOCKING LOGIC
    # -------------------------
    if sqli_flag:
        import re
        is_login_path = bool(re.search(r"/(login|signin|auth)", path, re.I))

        # Non-login → full block
        if not is_login_path:
            try:
                rdb.setex(f"sec:block:ip:{ip}", BF_IP_BLOCK_SECONDS, "1")
                rdb.setex(f"sec:block:reason:ip:{ip}", BF_IP_BLOCK_SECONDS, "sqli")
                if username:
                    rdb.setex(f"sec:block:user:{username}", BF_USER_LOCK_SECONDS, "1")
            except Exception:
                pass

            await write_log(
                ip, identifier, path, method,
                "blocked_by_firewall",
                f"sqli_score={sqli_score};{sqli_reason}",
            )

            log_console(ip, f"SQLI_BLOCKED score={sqli_score} reason={sqli_reason}")

            return render_timed_block_page(
                "Blocked: SQL Injection Detected",
                "Suspicious payload detected and blocked.",
                BF_IP_BLOCK_SECONDS,
                str(sqli_reason),
                status_code=403,
            )

        # Login → log only
        else:
            await write_log(
                ip, identifier, path, method,
                "sqli_suspect_login",
                f"{sqli_score};{sqli_reason}",
            )

    elif sqli_score >= 0.4:
        await write_log(
            ip, identifier, path, method,
            "sqli_suspect",
            f"{sqli_score};{sqli_reason}",
        )
    # -------------------------
    # XSS detection BEFORE forwarding
    # -------------------------
    try:
        xss_flag, xss_score, xss_reason = is_xss(combined_payload)
    except Exception as e:
        await write_log(ip, identifier, path, method, "xss_detector_error", str(e))
        # conservative fallback: treat as suspect (fail-closed if you prefer)
        xss_flag, xss_score, xss_reason = True, 1.0, f"detector_error:{e}"

    if xss_flag:
        # mirror SQLi handling: block high-confidence XSS on non-login paths
        import re
        is_login_path = bool(re.search(r"/(login|signin|auth)", path, re.I))
        if not is_login_path:
            try:
                rdb.setex(f"sec:block:ip:{ip}", BF_IP_BLOCK_SECONDS, "1")
                rdb.setex(f"sec:block:reason:ip:{ip}", BF_IP_BLOCK_SECONDS, "xss")
                if username:
                    rdb.setex(f"sec:block:user:{username}", BF_USER_LOCK_SECONDS, "1")
            except Exception:
                pass
            await write_log(ip, identifier, path, method, "blocked_by_firewall", f"xss_score={xss_score};{xss_reason}")
            log_console(ip, f"XSS_BLOCKED score={xss_score} reason={xss_reason}")
            return render_timed_block_page(
                "Blocked: XSS Detected",
                "Suspicious payload detected and blocked.",
                BF_IP_BLOCK_SECONDS,
                str(xss_reason),
                status_code=403,
            )
        else:
            # login endpoints: flag as suspect but avoid immediate lockout
            await write_log(ip, identifier, path, method, "xss_suspect_login", f"{xss_score};{xss_reason}")
    elif xss_score >= 0.35:
        # lower-confidence detection — log for analysis
        await write_log(ip, identifier, path, method, "xss_suspect", f"{xss_score};{xss_reason}")



    # Rate limiting & queueing
    try:
        ttl = penalty_ttl(ip)
        if ttl:
            await write_log(ip, identifier, path, method, "rate_limited", f"ttl={ttl}")
            return render_timed_block_page("Rate Limit Exceeded", "Too many requests.", ttl, "rate_limit", status_code=429)

        ok, reason = record_rate(ip)
        if not ok:
            ttl2 = penalty_ttl(ip) or 120
            await write_log(ip, identifier, path, method, "rate_limited", str(reason))
            return render_timed_block_page(
                "Rate Limit Exceeded", f"You exceeded rate ({reason}).", ttl2, str(reason), status_code=429
            )

        if not allowed_to_enter(ip,ua):
            await write_log(ip, identifier, path, method, "queued", "too_many_active_users")
            from security.protections.queue_control import get_active_count
            from security.state import MAX_ACTIVE_CLIENTS

            active = get_active_count()
            position = max(1, active - MAX_ACTIVE_CLIENTS + 1)
            return render_wait_page(position)

    except Exception as e:
        await write_log(ip, identifier, path, method, "rate_limiter_error", str(e))

    # Mark active (we're about to forward)
    mark_active(ip,ua)

    # Forward the request to backend
    try:
        print(">>> Trying to contact backend:", BACKEND_URL + path)
        print(">>> Using INTERNAL_SECRET:", INTERNAL_SECRET)

        resp = await app.state.http.request(
            method,
            BACKEND_URL + path,
            params=request.query_params,
            content=raw_body,
            headers=build_forward_headers(request, ip),
        )

        # ML prediction (best-effort async-style): if ml_predict_and_log present it will log ML events
        try:
            # ml_predict_and_log returns (flagged, score, reason)
            ml_flagged, ml_score, ml_reason = await ml_predict_and_log(request, raw_body, identifier)
            # write ml log to sqlite (already done inside ml_predict_and_log via write_ml_log)
        except Exception:
            pass

        # Inspect response for login failures and apply brute-force logic
        import re
        is_login_path = bool(re.search(r"/(login|signin|auth)", path, re.I))
        if is_login_path and method.upper() == "POST":
            resp_text = resp.text if hasattr(resp, "text") else (await resp.aread()).decode(errors="ignore")
            success = 200 <= resp.status_code < 300 and ("InvalidCredentials" not in resp_text and "UserNotFound" not in resp_text)
            if success:
                if username:
                    reset_fail_counters(username, ip)
                    await write_log(ip, identifier, path, method, "login_success", username)
            else:
                if username:
                    b_user, b_ip, reason = incr_fail_counters(username, ip)
                    await write_log(ip, identifier, path, method, "login_fail", reason)
                    if b_user:
                        users_ttl = is_user_blocked(username) or BF_USER_LOCK_SECONDS
                        return render_timed_block_page(
                            "Account Locked",
                            f"Too many failed login attempts for '{username}'.",
                            users_ttl,
                            "bruteforce",
                            status_code=403,
                        )
                    if b_ip:
                        ip_ttl = is_ip_blocked(ip) or BF_IP_BLOCK_SECONDS
                        return render_timed_block_page(
                            "IP Blocked",
                            "This IP has been temporarily blocked.",
                            ip_ttl,
                            "bruteforce",
                            status_code=403,
                        )
                else:
                    key = f"sec:fail:ip:{ip}"
                    try:
                        ic = rdb.incr(key)
                        if ic == 1:
                            rdb.expire(key, 900)
                        if int(ic) >= BF_MAX_FAILS_IP:
                            rdb.setex(f"sec:block:ip:{ip}", BF_IP_BLOCK_SECONDS, "1")
                            rdb.setex(f"sec:block:reason:ip:{ip}", BF_IP_BLOCK_SECONDS, "bruteforce")
                            rdb.delete(key)
                            ip_ttl = is_ip_blocked(ip) or BF_IP_BLOCK_SECONDS
                            return render_timed_block_page(
                                "IP Blocked",
                                "This IP has been temporarily blocked due to suspicious login activity.",
                                ip_ttl,
                                "bruteforce",
                                status_code=403,
                            )
                    except Exception:
                        pass

        # mark active again (successful forward)
        mark_active(ip,ua)
        await write_log(ip, identifier, path, method, "allowed", str(resp.status_code))

        skip_headers = {
            "connection", "keep-alive", "transfer-encoding", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "upgrade", "content-encoding"
        }
        sanitized = {k: v for k, v in resp.headers.items() if k.lower() not in skip_headers}
        return Response(content=resp.content, status_code=resp.status_code, headers=sanitized)

    except Exception as e:
        import traceback
        traceback.print_exc()
        print("----- DEBUG INFO -----")
        print("BACKEND_URL:", BACKEND_URL)
        print("ERROR:", repr(e))
        print("----------------------")
        await write_log(ip, identifier, path, method, "backend_unreachable", str(e))
        return render_backend_error()


# If you run standalone for quick tests:
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(PROXY_PORT or 8000))


