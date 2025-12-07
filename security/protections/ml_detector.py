# security/protections/ml_detector.py
"""
Lightweight AI-style anomaly detector for request payloads.

Purpose:
 - Combine heuristic signals (SQLi, brute-force patterns, bot indicators)
   into a single suspicion score.
 - Log results for model retraining or admin dashboard visualization.
 - Fail closed for strict security posture.

Thresholds:
 - score >= 0.5 → treated as malicious
 - score >= 0.3 → logged for analysis
"""

from ..logs.sqlite_logger import write_ml_log
from .sqli_detector import is_sqli
import asyncio
import re


async def ml_predict_and_log(request, body_bytes, identifier: str):
    """
    Hybrid heuristic model (ML-like behavior).

    Returns:
        (flagged: bool, score: float, reason: str)
    """
    try:
        body = body_bytes.decode(errors="ignore") if body_bytes else ""
        score = 0.0
        reasons = []

        # 1. SQL Injection scoring
        sqli_flag, sqli_score, sqli_reason = is_sqli(body)
        if sqli_flag:
            score += min(0.8, sqli_score)
            reasons.append(f"sqli:{sqli_reason}")

        # 2. Password brute-force related content
        if re.search(r"(password|passwd|login|auth)", body, re.IGNORECASE):
            score += 0.15
            reasons.append("has_auth_pattern")

        # 3. Suspicious User-Agent patterns
        ua = (request.headers.get("user-agent") or "").lower()
        if not ua or len(ua) < 6:
            score += 0.15
            reasons.append("missing_ua")
        elif any(bot_kw in ua for bot_kw in ("curl", "python", "wget", "java/", "scrapy", "requests")):
            score += 0.18
            reasons.append("suspicious_ua")

        # 4. Excessive body size / unusual input density
        if len(body) > 2000 and len(set(body)) < 60:
            score += 0.1
            reasons.append("compressed_payload")

        # 5. Repeated suspicious keywords
        if len(re.findall(r"(select|union|insert|update|delete|drop)", body, re.IGNORECASE)) > 3:
            score += 0.2
            reasons.append("keyword_spam")

        # Cap score to 1.0
        if score > 1.0:
            score = 1.0

        reason_str = ";".join(reasons) if reasons else "normal"
        client_ip = identifier.split(":")[0] if identifier else "unknown"

        # Log if above mild threshold or contains SQLi indicators
        if score >= 0.3 or sqli_flag:
            await write_ml_log(client_ip, request.url.path, round(score, 2), reason_str)

        # Strict blocking if score >= 0.5
        return (score >= 0.5), float(round(score, 2)), reason_str

    except Exception as e:
        # Fail closed for strict posture
        return True, 1.0, f"error:{e}"
