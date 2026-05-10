"""
Rule-based fallback classifier used when the DistilBERT model is not yet trained.
Scores text using keyword frequency to produce pseudo-probability distributions.
"""

import re
from typing import Dict

from config.settings import CYBER_KEYWORDS, THREAT_CLASSES


def _score_text(text: str) -> Dict[str, float]:
    """Return raw keyword-match scores per threat class."""
    text_lower = text.lower()
    scores = {cls: 0.0 for cls in THREAT_CLASSES}

    PHRASE_RULES = {
        "Ransomware": [
            "files have been encrypted", "pay 0.5 bitcoin", "bitcoin within",
            "restore access", "data loss", "files have been locked",
            "decryption key", "ransom", "encrypted", "48 hours", "72 hours",
        ],
        "SQL Injection": [
            "or 1=1", "' or", "bypasses login", "unauthorized access to the database",
            "query bypasses", "sql injection", "union select", "drop table",
        ],
        "DDoS": [
            "millions of requests per second", "requests per second",
            "causing it to slow down", "eventually crash", "bots are sending",
            "syn flood", "udp flood", "denial of service", "ddos",
        ],
        "Malware": [
            "secretly installs background processes", "steal browser cookies",
            "saved passwords", "installs background", "free pdf converter",
            "keylogger", "trojan", "backdoor", "rootkit", "spyware",
        ],
        "Phishing": [
            "click here", "verify your account", "suspended", "unusual activity",
            "confirm your password", "bank account", "urgent action",
        ],
        "Benign": [
            "security patch", "audit completed", "firewall updated", "vpn access",
        ],
    }

    for cls, phrases in PHRASE_RULES.items():
        for phrase in phrases:
            if phrase in text_lower:
                scores[cls] += 10.0

    keyword_map = {
        "Benign": "benign", "Phishing": "phishing", "Malware": "malware",
        "Ransomware": "ransomware", "DDoS": "ddos", "SQL Injection": "sql_injection",
    }
    for threat, key in keyword_map.items():
        for kw in CYBER_KEYWORDS.get(key, []):
            if kw in text_lower:
                scores[threat] += 1.0

    return scores


def rule_based_predict(text: str) -> Dict:
    """
    Keyword-frequency prediction returning the same schema as ThreatClassifier.predict().
    """
    raw = _score_text(text)
    total = sum(raw.values()) or 1.0  # avoid division by zero

    # Normalize to pseudo-probabilities
    probs = {cls: raw[cls] / total for cls in THREAT_CLASSES}

    # If nothing matched, call it Benign with high confidence
    if total == 1.0:
        probs = {cls: (1.0 if cls == "Benign" else 0.0) for cls in THREAT_CLASSES}

    best = max(probs, key=probs.get)
    confidence = probs[best]

    return {
        "predicted_label": best,
        "predicted_id":    THREAT_CLASSES.index(best),
        "confidence":      confidence,
        "probabilities":   probs,
        "source":          "rule_based",
    }
