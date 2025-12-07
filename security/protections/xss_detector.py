"""
Lightweight XSS detector.

Returns (flagged: bool, score: float, reason: str)

Design:
 - Canonicalize input (URL decode, html unescape, normalize).
 - Apply strong/medium/weak regex rules for common XSS vectors:
   <script> tags, event handlers (onerror, onclick), javascript: URIs,
   inline SVG payloads, attribute injection patterns, encoded payloads.
 - Score is additive; flagged if score >= 0.45 (tunable).
"""

import re
import urllib.parse
import html
import unicodedata
from typing import Tuple

MAX_INPUT_LEN = 16 * 1024

STRONG_PATTERNS = [
    r"<\s*script\b",                # <script ...>
    r"&#x3[cC];\s*script",          # encoded <script
    r"on\w+\s*=",                   # event handlers: onerror= onclick= onload=
    r"javascript\s*:",              # javascript: URIs
    r"<\s*svg\b.*on\w+\s*=",        # svg with onload/onerror
    r"<\s*img\b.*on\w+\s*=",        # img onerror / onload
]

MEDIUM_PATTERNS = [
    r"document\.cookie",            # attempts to read cookies
    r"document\.write\s*\(",        # writing HTML
    r"innerHTML\s*=",               # DOM insertion
    r"eval\s*\(",                   # JS eval usage
    r"setTimeout\s*\(\s*['\"]",     # strings passed to setTimeout
    r"<\s*iframe\b",                # iframe tags
    r"srcdoc\s*=",                  # srcdoc attribute
]

WEAK_PATTERNS = [
    r"%3Cscript%3E",                # double-encoded script tag
    r"&lt;script&gt;",              # html-escaped script tag
    r"&#x3c;script&#x3e;",          # alternate encoding
    r"\b(alert|confirm|prompt)\s*\(",  # obvious JS functions used in payloads
]

STRONG_RE = re.compile("|".join(STRONG_PATTERNS), re.IGNORECASE | re.DOTALL)
MEDIUM_RE = re.compile("|".join(MEDIUM_PATTERNS), re.IGNORECASE)
WEAK_RE = re.compile("|".join(WEAK_PATTERNS), re.IGNORECASE)

def _multi_url_unquote(s: str, iterations: int = 4) -> str:
    out = s or ""
    try:
        for _ in range(iterations):
            decoded = urllib.parse.unquote_plus(out)
            if decoded == out:
                break
            out = decoded
    except Exception:
        pass
    return out

def _canonicalize(s: str) -> str:
    if not s:
        return ""
    try:
        s = _multi_url_unquote(s, iterations=6)
    except Exception:
        pass
    try:
        s = html.unescape(s)
    except Exception:
        pass
    s = unicodedata.normalize("NFKC", s)
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) > MAX_INPUT_LEN:
        s = s[:MAX_INPUT_LEN]
    return s

def is_xss(payload: str) -> Tuple[bool, float, str]:
    """
    Returns (flagged, score, reason)
    flagged True when score >= 0.45
    """
    p = _canonicalize(payload or "")
    if not p:
        return False, 0.0, "empty"

    score = 0.0
    reasons = set()

    if STRONG_RE.search(p):
        score += 0.5
        reasons.add("strong")

    if MEDIUM_RE.search(p):
        score += 0.25
        reasons.add("medium")

    if WEAK_RE.search(p):
        score += 0.1
        reasons.add("weak")

    # multiple occurrences of script-like tokens increases suspicion
    kw_count = len(re.findall(r"(script|on\w+|javascript:|iframe|svg|img)", p, flags=re.IGNORECASE))
    if kw_count >= 2:
        score += min(0.25, 0.06 * kw_count)
        reasons.add("multi_kw")

    # short payloads should be less penalized
    if len(p) < 6:
        score = max(0.0, score - 0.08)

    score = min(1.0, score)
    reason_str = ",".join(sorted(reasons)) if reasons else "none"
    flagged = score >= 0.45

    return flagged, float(round(score, 2)), reason_str
