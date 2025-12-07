import re
import urllib.parse
import html
import unicodedata
from typing import Tuple

MAX_LEN = 20000

# ============================================================
# CRITICAL IMMEDIATE BLOCK
# ============================================================
IMMEDIATE = re.compile(
    r"(?i)("
    r"union\s+all\s+select|union\s+select|"
    r"information_schema|"
    r"(updatexml|extractvalue)\s*\(|"
    r"load_file\s*\(|into\s+(outfile|dumpfile)|"
    r"sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|"
    r"0x[0-9a-f]{6,}|"
    r";\s*(drop|alter|truncate|create|insert|update|delete)\b"
    r")"
)

# ============================================================
# IMPROVED UNIVERSAL TAUTOLOGY
# Catches:
# '1'='1'
# "a"="a"
# 1=1
# '1' AND '1'='1'
# 1 AND 1=1
# ============================================================
UNIVERSAL_TAUTOLOGY = re.compile(
    r"(?i)\b(and|or)\b.*?([\"'`]?)([A-Za-z0-9]+)\2\s*=\s*\2\3\2"
)

# Simple a=a or '1'='1'
WEAK_TAUTOLOGY = re.compile(
    r"(?i)([\"'`]?)([A-Za-z0-9]+)\1\s*=\s*\1([A-Za-z0-9]+)\1"
)

# Numeric tautologies
NUM_TAUTOLOGY = re.compile(
    r"(?i)\b(and|or)\b\s*\(?\s*\d+\s*=\s*\d+\s*\)?"
)

# Stacked query
STACKED = re.compile(
    r"(?i)(;|%3b)\s*(select|insert|update|delete|drop|alter|create)"
)

# SQL keyword cluster
SQL_KEYWORDS = re.compile(
    r"(?i)\b(select|union|insert|update|delete|drop|alter|truncate|exec|from|where|having|order|group)\b"
)

# Comments
COMMENTS = re.compile(r"(?i)(--|#|/\*|\*/)")

# ============================================================
# CANONICALIZATION
# ============================================================
def _canon(s: str) -> str:
    if not s:
        return ""

    # multi url decode
    for _ in range(6):
        decoded = urllib.parse.unquote_plus(s)
        if decoded == s:
            break
        s = decoded

    # html decode twice
    s = html.unescape(s)
    s = html.unescape(s)

    # strip SQL comments
    s = re.sub(r"/\*.*?\*/", "", s)
    s = re.sub(r"--.*?$", "", s, flags=re.MULTILINE)

    s = unicodedata.normalize("NFKC", s)
    s = re.sub(r"\s+", " ", s).strip().lower()

    return s[:MAX_LEN]

# ============================================================
# MAIN DETECTOR
# ============================================================
def is_sqli(payload: str) -> Tuple[bool, float, str]:
    p = _canon(payload)
    if not p:
        return False, 0.0, "empty"

    # ===== HARD BLOCK =====
    if IMMEDIATE.search(p):
        return True, 0.98, "immediate_block"

    score = 0.0
    reasons = []

    # ===== Tautologies =====
    if UNIVERSAL_TAUTOLOGY.search(p):
        score += 0.45
        reasons.append("universal_tautology")

    if NUM_TAUTOLOGY.search(p):
        score += 0.30
        reasons.append("numeric_tautology")

    # Proper weak tautology handling
    for full, left, right in WEAK_TAUTOLOGY.findall(p):
        if left == right:  # a=a or '1'='1'
            score += 0.20
            reasons.append("weak_tautology")
            break

    # ===== Stacked queries =====
    if STACKED.search(p):
        score += 0.25
        reasons.append("stacked_query")

    # ===== Comment bypass =====
    if COMMENTS.search(p):
        score += 0.15
        reasons.append("comment")

    # ===== Keyword cluster =====
    kw = SQL_KEYWORDS.findall(p)
    if len(kw) >= 3:
        score += min(0.40, len(kw) * 0.10)
        reasons.append("keyword_cluster")

    # ===== Encoded payloads =====
    hex_hits = len(re.findall(r"0x[0-9a-f]{2,}", p))
    if hex_hits:
        score += min(0.25, hex_hits * 0.10)
        reasons.append("encoded_payload")

    # Short input discounts
    if len(p) < 6:
        score -= 0.05

    score = max(0.0, min(1.0, round(score, 2)))
    flagged = score >= 0.40

    return flagged, score, ",".join(reasons) if reasons else "none"
