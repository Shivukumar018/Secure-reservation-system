import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import pytz
from datetime import datetime
import redis
from typing import List

# =======================================
# CONFIG
# =======================================
PROXY_BASE = "http://localhost:8000"
DEFAULT_ADMIN_TOKEN = "ShivuSecureAdminToken123"
DASHBOARD_TITLE = "Golden Express — Security Admin Dashboard"
IST = pytz.timezone("Asia/Kolkata")

# =======================================
# STREAMLIT SETUP (LIGHT MODE)
# =======================================
st.set_page_config(page_title=DASHBOARD_TITLE, layout="wide")

# Light clean design
st.markdown("""
    <style>
        body { background-color: #ffffff; }
        .stMetric { font-size: 18px; }
    </style>
""", unsafe_allow_html=True)

st.markdown(f"<h1 style='margin-bottom:10px'>{DASHBOARD_TITLE}</h1>", unsafe_allow_html=True)

session = requests.Session()

# =======================================
# HELPERS
# =======================================
def get_auth_headers():
    token = st.session_state.get("admin_token", "")
    return {"Authorization": f"Bearer {token}"} if token else {}

def api_get(path, params=None):
    try:
        r = session.get(f"{PROXY_BASE}{path}", params=params or {}, headers=get_auth_headers(), timeout=6)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def api_post(path, data=None):
    try:
        r = session.post(f"{PROXY_BASE}{path}", data=data or {}, headers=get_auth_headers(), timeout=6)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, {"text": r.text}
    except Exception as e:
        return 500, {"error": str(e)}

@st.cache_data(ttl=5)
def fetch_logs(limit=500):
    res = api_get(f"/admin/logs?limit={limit}")
    if "logs" not in res:
        return pd.DataFrame()
    df = pd.DataFrame(res["logs"])
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], format="%d %b %Y, %I:%M:%S %p", errors="coerce")
        df["ts"] = df["ts"].dt.strftime("%d %b %Y, %I:%M:%S %p")
    return df

# Categorization improved for blocked analytics
def categorize_log(row):
    outcome = (row.get("outcome") or "").lower()
    reason = (row.get("reason") or "").lower()

    if "sqli" in reason:
        return "SQLi"
    if "xss" in reason:
        return "XSS"
    if "rate" in reason:
        return "DoS"
    if "brute" in reason or "login_fail" in outcome:
        return "BruteForce"
    if "blocked" in outcome:
        return "Blocked"

    return "Other"

def fetch_blocked_ips_from_api():
    res = api_get("/admin/blocked_ips")
    if "blocked" in res:
        return res["blocked"]
    return []

def redis_unblock_ips(ips: List[str]):
    failed = []
    try:
        rdb = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    except Exception:
        return 0, ips

    unblocked = 0
    for ip in ips:
        try:
            # Brute-force blocks
            rdb.delete(f"sec:block:ip:{ip}")
            rdb.delete(f"sec:block:ip:{ip}:temp")
            rdb.delete(f"sec:block:reason:ip:{ip}")
            rdb.delete(f"sec:block:reason:ip:{ip}:temp")

            # Rate limiter penalties
            rdb.delete(f"sec:penalty:{ip}")
            rdb.delete(f"sec:penalty:reason:{ip}")

            unblocked += 1

        except Exception:
            failed.append(ip)

    return unblocked, failed
# =======================================
# AUTH / LOGIN
# =======================================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "admin_token" not in st.session_state:
    st.session_state.admin_token = ""

if not st.session_state.logged_in:
    with st.form("login_form"):
        st.subheader("Admin Login")
        token_input = st.text_input("Admin Token", value=DEFAULT_ADMIN_TOKEN, type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            code, res = api_post("/admin/login", {"token": token_input})
            if code == 200 and res.get("detail") == "login_success":
                st.session_state.logged_in = True
                st.session_state.admin_token = token_input
                st.success("Logged in successfully.")
                st.rerun()
            else:
                st.error("Invalid token or proxy not reachable.")
    st.stop()

# =======================================
# SIDEBAR
# =======================================
page = st.sidebar.radio("Navigation", ["Dashboard", "Logs", "Blocked Analytics", "Blocked IPs"])
st.sidebar.markdown("---")

if st.sidebar.button("Refresh"):
    st.cache_data.clear()
    st.rerun()

if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.admin_token = ""
    st.cache_data.clear()
    st.rerun()

# =======================================
# DASHBOARD
# =======================================
if page == "Dashboard":
    st.subheader("Protection Status")

    status = api_get("/admin/status")

    if "error" in status:
        st.error(f"Proxy not reachable: {status['error']}")
        mode = "UNKNOWN"
        active = 0
    else:
        mode = status.get("mode", "UNKNOWN")
        active = status.get("active_users", 0)

    color = "#27ae60" if mode.upper() == "STRICT" else "#c0392b"

    st.markdown(
        f"<div style='background:{color};color:white;padding:8px;border-radius:8px;"
        f"width:250px;text-align:center;font-weight:600'>{mode}</div>",
        unsafe_allow_html=True
    )

    st.metric("Active Users", active)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Enable Protection"):
            code, res = api_post("/admin/mode", {"mode": "strict"})
            if code == 200:
                st.cache_data.clear()
                st.rerun()
    with col2:
        if st.button("Disable Protection"):
            code, res = api_post("/admin/mode", {"mode": "raw"})
            if code == 200:
                st.cache_data.clear()
                st.rerun()

# =======================================
# LOGS (ONLY BLOCKED LOGS)
# =======================================
elif page == "Logs":
    st.subheader("Blocked Logs Only")

    df = fetch_logs()

    if df.empty:
        st.info("No logs found.")
    else:
        df["Category"] = df.apply(categorize_log, axis=1)

        blocked_df = df[df["Category"].isin(["SQLi", "XSS", "DoS", "BruteForce", "Blocked"])]

        if blocked_df.empty:
            st.success("No blocked logs yet. System clean.")
        else:
            cols_to_show = ["ts", "client_ip", "path", "method", "outcome", "reason", "Category"]
            blocked_df = blocked_df[cols_to_show]

            st.dataframe(blocked_df, width="stretch")

# =======================================
# BLOCKED ANALYTICS
# =======================================
elif page == "Blocked Analytics":
    st.subheader("Blocked Requests Overview")

    status = api_get("/admin/status")
    st.metric("Active Users", status.get("active_users", 0))

    df = fetch_logs()
    if df.empty:
        st.info("No data available.")
    else:
        df["Category"] = df.apply(categorize_log, axis=1)

        blocked_df = df[df["Category"].isin(["SQLi", "XSS", "DoS", "BruteForce"])]

        if blocked_df.empty:
            st.info("No blocked requests recorded.")
        else:
            fig = px.histogram(
                blocked_df,
                x="Category",
                title="Blocked Requests Distribution",
                text_auto=True
            )
            st.plotly_chart(fig, width="stretch")

# =======================================
# BLOCKED IPS
# =======================================
elif page == "Blocked IPs":
    st.subheader("Blocked IPs")

    blocked = fetch_blocked_ips_from_api()
    if not blocked:
        st.success("No IPs are currently blocked.")
    else:
        df = pd.DataFrame(blocked)
        df.rename(columns={"ip": "IP", "ttl": "TTL", "reason": "Reason"}, inplace=True)
        st.dataframe(df, width="stretch")

        selected = st.multiselect("Select IPs to unblock", df["IP"].tolist())
        if selected and st.button("Unblock"):
            for ip in selected:
                api_post("/admin/unblock", {"ip": ip})
            st.success("Selected IPs unblocked.")
            st.cache_data.clear()
            st.rerun()

