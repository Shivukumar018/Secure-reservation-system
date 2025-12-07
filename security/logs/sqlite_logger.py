# security/logs/sqlite_logger.py
import sqlite3
import asyncio
from ..state import DB_FILE, ist_now
import time

CREATE_LOGS = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    client_ip TEXT,
    identifier TEXT,
    path TEXT,
    method TEXT,
    outcome TEXT,
    reason TEXT
)"""
CREATE_ML = """
CREATE TABLE IF NOT EXISTS ml_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    client_ip TEXT,
    path TEXT,
    score REAL,
    reason TEXT
)"""

def _init_db_sync():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=5)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute(CREATE_LOGS)
    cur.execute(CREATE_ML)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ml_ts ON ml_logs(ts);")
    conn.commit()
    conn.close()

async def init_db():
    await asyncio.to_thread(_init_db_sync)

def _exec_with_retry(func, retries=3, backoff=0.05):
    for i in range(retries):
        try:
            return func()
        except sqlite3.OperationalError as e:
            if 'locked' in str(e).lower() and i < retries - 1:
                time.sleep(backoff * (i + 1))
                continue
            raise

def _write_log_sync(client_ip, identifier, path, method, outcome, reason=""):
    def job():
        conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=5)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (ts, client_ip, identifier, path, method, outcome, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ist_now(), client_ip, identifier or "", path, method, outcome, reason),
        )
        conn.commit()
        conn.close()
    _exec_with_retry(job)

def _write_ml_log_sync(client_ip, path, score, reason=""):
    def job():
        conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=5)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO ml_logs (ts, client_ip, path, score, reason) VALUES (?, ?, ?, ?, ?)",
            (ist_now(), client_ip, path, float(score or 0.0), reason or ""),
        )
        conn.commit()
        conn.close()
    _exec_with_retry(job)

async def write_log(client_ip, identifier, path, method, outcome, reason=""):
    await asyncio.to_thread(_write_log_sync, client_ip, identifier, path, method, outcome, reason)

async def write_ml_log(client_ip, path, score, reason=""):
    await asyncio.to_thread(_write_ml_log_sync, client_ip, path, score, reason)
