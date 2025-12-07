from fastapi.responses import HTMLResponse
from security.state import ist_now, INTERNAL_SECRET
import html
from typing import Dict

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade"
}

def log_console(ip: str, msg: str):
    # lightweight console logger; swap to logging module as needed
    print(f"[{ist_now()}] {ip} | {msg}")

def render_wait_page(position: int):
    html_doc = f"""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Server Busy</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #f6f7fb;
                color: #333;
                text-align: center;
                padding-top: 10%;
            }}
            .card {{
                display: inline-block;
                background: #fff;
                padding: 2rem 3rem;
                border-radius: 10px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }}
            h1 {{
                margin-bottom: 1rem;
                color: #c0392b;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Server Busy</h1>
            <p>You are currently in queue.</p>
            <p><strong>Your position: {position}</strong></p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_doc, status_code=200)

from fastapi.responses import HTMLResponse
import html
def render_timed_block_page(
        title: str,
        message: str,
        ttl_seconds: int,
        reason: str = "",
        status_code: int = 403
    ):
    import html
    from fastapi.responses import HTMLResponse

    # Convert TTL to readable form
    try:
        ttl = int(ttl_seconds)
    except:
        ttl = 0

    if ttl <= 60:
        eta = f"{ttl} seconds"
    elif ttl < 3600:
        eta = f"{ttl // 60} minutes"
    else:
        h = ttl // 3600
        m = (ttl % 3600) // 60
        eta = f"{h} hours {m} minutes" if m else f"{h} hours"

    reason_html = (
        f"<p class='reason'><b>Technical reason:</b> {html.escape(reason)}</p>"
        if reason else ""
    )

    html_doc = f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<style>

    body {{
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif;
        background: linear-gradient(135deg, #e3f2ff, #ffffff, #fbe8ff, #fff4e6);
        background-size: 300% 300%;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        color: #222;
    }}

    /* CARD (static, no animation) */
    .card {{
        width: 460px;
        padding: 45px;
        border-radius: 22px;
        background: white;
        border: 2px solid #e5e8ef;
        box-shadow:
            0 6px 18px rgba(0,0,0,0.07),
            0 0 0 6px rgba(26,115,232,0.10);
        text-align: center;
    }}

    /* Static colourful border highlight */
    .card::before {{
        content: "";
        position: absolute;
        inset: -3px;
        border-radius: 24px;
        z-index: -1;
        background: linear-gradient(135deg,
            #1a73e8,
            #ff6ec7,
            #ffb74d,
            #42a5f5
        );
        filter: blur(18px);
        opacity: 0.55;
    }}

    /* ICON (static, colourful) */
    .icon-wrap {{
        width: 85px;
        height: 85px;
        margin: 0 auto 18px;
        border-radius: 50%;
        background: linear-gradient(135deg, #1a73e8, #64b5f6);
        display: flex;
        justify-content: center;
        align-items: center;
        color: white;
        font-size: 42px;
        box-shadow: 0 4px 12px rgba(26,115,232,0.4);
    }}

    h1 {{
        font-size: 2rem;
        margin-bottom: 10px;
        font-weight: 700;
        color: #1a73e8;
    }}

    p {{
        font-size: 1.05rem;
        margin: 8px 0;
        line-height: 1.45;
    }}

    .reason {{
        color: #555;
        font-size: 0.9rem;
        margin-top: 10px;
    }}

    .eta {{
        margin-top: 16px;
        color: #1a73e8;
        font-size: 1.2rem;
        font-weight: 600;
    }}

    footer {{
        margin-top: 26px;
        opacity: 0.7;
        font-size: 0.85rem;
    }}

</style>
</head>

<body>

<div class="card">

    <div class="icon-wrap">🔒</div>

    <h1>{html.escape(title)}</h1>

    <p>{html.escape(message)}</p>
    {reason_html}

    <p class="eta">Try again after: {eta}</p>

    <footer>Golden Express Security Firewall</footer>
</div>

</body>
</html>
"""

    return HTMLResponse(content=html_doc, status_code=status_code)

def render_backend_error():
    html_doc = (
        "<!doctype html><html><head><meta charset='utf-8'><title>Service Unavailable</title></head>"
        "<body style='font-family:Arial;text-align:center;margin-top:10%;background:#f8f8f8;color:#333'>"
        "<div style='display:inline-block;padding:24px;background:white;border-radius:10px;box-shadow:0 0 8px #ccc;'>"
        "<h2>Service Unavailable</h2><p>The backend service is unreachable. Please try again later.</p></div></body></html>"
    )
    return HTMLResponse(content=html_doc, status_code=502)

def build_forward_headers(request, client_ip: str) -> Dict[str, str]:
    headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk == "host":
            continue
        headers[k] = v
    existing = request.headers.get("x-forwarded-for")
    headers["x-forwarded-for"] = f"{existing}, {client_ip}" if existing else client_ip
    headers["via"] = "1.1 security-proxy"

    # ensure no accidental spaces or newline characters in the secret
    headers["x-internal-secret"] = INTERNAL_SECRET.strip()

    return headers
