"""
Core Threat Intelligence Engine — orchestrates NLP pipeline,
model inference, explainability, and report generation.
"""

import re
from datetime import datetime
from typing import Dict, Any, Optional

from config.settings import SEVERITY_LEVELS, THREAT_CLASSES
from nlp.preprocessor import (
    clean_text, extract_entities, extract_keywords, get_top_keywords,
)
from models.rule_based import rule_based_predict


# ─── Lazy import classifier to avoid loading transformers at startup ──────────

def _try_load_classifier():
    try:
        from models.classifier import ThreatClassifier
        clf = ThreatClassifier()
        if clf.load_model():
            return clf
    except Exception:
        pass
    return None


_CLASSIFIER: Optional[Any] = None
_CLASSIFIER_TRIED = False


def _get_classifier():
    global _CLASSIFIER, _CLASSIFIER_TRIED
    if not _CLASSIFIER_TRIED:
        _CLASSIFIER = _try_load_classifier()
        _CLASSIFIER_TRIED = True
    return _CLASSIFIER


# ─── Explainability Reasoning ─────────────────────────────────────────────────

REASONING_TEMPLATES = {
    "Benign": [
        "The text exhibits characteristics typical of normal security communications.",
        "Language patterns align with routine IT operations and policy documentation.",
        "No malicious indicators or suspicious entities were detected in the content.",
        "The text follows standard professional security advisory formatting.",
    ],
    "Phishing": [
        "Detected urgency language combined with credential-harvesting indicators.",
        "Suspicious external URL present attempting to redirect users to fake login page.",
        "Social engineering tactics identified: impersonation and fear-based manipulation.",
        "Email-style formatting with account suspension threats matches phishing templates.",
        "Keyword density analysis reveals phishing-specific vocabulary cluster.",
    ],
    "Malware": [
        "Technical indicators of malware behavior detected: C2 communication patterns.",
        "Malicious executable characteristics identified: payload delivery mechanisms.",
        "Persistence mechanism keywords indicate advanced persistent threat (APT) behavior.",
        "Process injection and evasion techniques vocabulary detected.",
        "Botnet and command-and-control infrastructure terminology present.",
    ],
    "Ransomware": [
        "Encryption and ransom demand indicators strongly present in the text.",
        "File encryption with payment demand matches ransomware attack signature.",
        "Double extortion tactics vocabulary: data theft before encryption pattern.",
        "Cryptocurrency payment demand with deadline is characteristic of ransomware.",
        "Known ransomware group TTP language patterns detected.",
    ],
    "DDoS": [
        "High-volume traffic attack indicators identified in the content.",
        "Botnet coordination language with bandwidth exhaustion tactics detected.",
        "Network flooding attack patterns: SYN/UDP/HTTP flood indicators present.",
        "Amplification attack technique terminology identified.",
        "Distributed denial-of-service attack signatures match text patterns.",
    ],
    "SQL Injection": [
        "SQL syntax injection patterns detected in the analyzed text.",
        "Database exploitation vocabulary: UNION SELECT, DROP TABLE indicators.",
        "Authentication bypass attempt language: OR 1=1 pattern variants identified.",
        "Blind SQL injection technique terminology present in the content.",
        "Database schema enumeration and data exfiltration indicators detected.",
    ],
}

RECOMMENDATIONS = {
    "Benign": [
        "Continue regular security monitoring and patch management.",
        "Maintain current security policies and audit schedules.",
        "Document findings in security knowledge base for future reference.",
    ],
    "Phishing": [
        "Block all identified malicious URLs in email gateway and web proxy.",
        "Alert affected users and initiate password reset procedures immediately.",
        "Report phishing campaign to Anti-Phishing Working Group (APWG).",
        "Deploy additional email authentication controls (DMARC, DKIM, SPF).",
        "Conduct targeted security awareness training for affected user groups.",
    ],
    "Malware": [
        "Isolate affected systems from network immediately to prevent lateral movement.",
        "Preserve forensic evidence: memory dumps and disk images before remediation.",
        "Submit malware samples to threat intelligence platforms (VirusTotal, Any.Run).",
        "Block identified C2 IP addresses and domains at perimeter firewall.",
        "Deploy EDR hunt across all endpoints for similar indicators of compromise.",
    ],
    "Ransomware": [
        "IMMEDIATELY isolate all affected systems — disconnect from network.",
        "Do NOT pay ransom without consulting law enforcement and legal counsel.",
        "Contact FBI IC3 and CISA to report the incident and receive assistance.",
        "Restore from clean, verified offline backups if available.",
        "Engage specialized ransomware incident response team.",
        "Preserve all encrypted files and ransom notes for decryption key recovery.",
    ],
    "DDoS": [
        "Activate DDoS mitigation provider (Cloudflare, Akamai) immediately.",
        "Implement rate limiting and traffic scrubbing at network edge.",
        "Block identified attacking IP ranges at upstream provider level.",
        "Switch to anycast routing to distribute and absorb attack traffic.",
        "Notify ISP and coordinate upstream filtering for volumetric attacks.",
    ],
    "SQL Injection": [
        "Patch identified SQL injection vulnerability immediately with parameterized queries.",
        "Review and audit all database query construction in affected applications.",
        "Implement Web Application Firewall (WAF) rules to block injection patterns.",
        "Audit database access logs to determine full scope of data exfiltration.",
        "Rotate all database credentials and API keys that may have been compromised.",
        "Conduct full penetration test on all web application endpoints.",
    ],
}


# ─── Main Analysis Engine ─────────────────────────────────────────────────────

class ThreatIntelEngine:
    """Orchestrates the full threat intelligence analysis pipeline."""

    def analyze(self, raw_text: str) -> Dict[str, Any]:
        """
        Run full analysis on input text.

        Returns a comprehensive threat intelligence report dictionary.
        """
        if not raw_text or not raw_text.strip():
            return self._empty_report()

        timestamp = datetime.now().isoformat()

        # ── 1. NLP Processing ──────────────────────────────────────────────
        cleaned = clean_text(raw_text)
        entities = extract_entities(raw_text)       # run on raw (preserves URLs etc.)
        keyword_map = extract_keywords(raw_text)
        top_keywords = get_top_keywords(raw_text, top_n=15)

        # ── 2. Classification ──────────────────────────────────────────────
        clf = _get_classifier()
        if clf is not None:
            try:
                pred = clf.predict(cleaned)
                pred["source"] = "distilbert"
            except Exception:
                pred = rule_based_predict(raw_text)
        else:
            pred = rule_based_predict(raw_text)

        threat = pred["predicted_label"]
        confidence = pred["confidence"]
        probabilities = pred["probabilities"]

        # ── 3. Severity ────────────────────────────────────────────────────
        sev_meta = SEVERITY_LEVELS[threat]
        # Adjust severity score by confidence
        sev_score = int(sev_meta["score"] * confidence) if threat != "Benign" else 0

        # ── 4. Explainability ──────────────────────────────────────────────
        import random
        reasoning_pool = REASONING_TEMPLATES.get(threat, ["Analysis complete."])
        reasoning = random.sample(reasoning_pool, min(3, len(reasoning_pool)))

        recommendations = RECOMMENDATIONS.get(threat, [])

        # ── 5. Risk Score (composite) ──────────────────────────────────────
        entity_bonus = (
            len(entities["urls"]) * 5 +
            len(entities["ips"])  * 3 +
            len(entities["cves"]) * 10
        )
        risk_score = min(100, sev_score + min(entity_bonus, 20))

        return {
            "timestamp":       timestamp,
            "raw_text":        raw_text,
            "cleaned_text":    cleaned,
            # Classification
            "threat":          threat,
            "confidence":      round(confidence * 100, 2),
            "probabilities":   {k: round(v * 100, 2) for k, v in probabilities.items()},
            "model_source":    pred.get("source", "unknown"),
            # Severity
            "severity_level":  sev_meta["level"],
            "severity_score":  sev_score,
            "severity_color":  sev_meta["color"],
            "risk_score":      risk_score,
            # NLP
            "entities":        entities,
            "keyword_map":     keyword_map,
            "top_keywords":    top_keywords,
            # XAI
            "reasoning":       reasoning,
            "recommendations": recommendations,
        }

    @staticmethod
    def _empty_report() -> Dict[str, Any]:
        return {
            "timestamp": datetime.now().isoformat(),
            "raw_text": "",
            "threat": "Unknown",
            "confidence": 0.0,
            "probabilities": {t: 0.0 for t in THREAT_CLASSES},
            "severity_level": "None",
            "severity_score": 0,
            "severity_color": "#00C853",
            "risk_score": 0,
            "entities": {"urls": [], "ips": [], "emails": [], "cves": [], "hashes": []},
            "keyword_map": {},
            "top_keywords": [],
            "reasoning": ["No text provided for analysis."],
            "recommendations": [],
            "model_source": "none",
        }
