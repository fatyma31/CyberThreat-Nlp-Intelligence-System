"""
Global Configuration Settings for Cyber Threat Intelligence System
"""

import os
from pathlib import Path

# ─── Project Paths ───────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models" / "saved"
REPORTS_DIR = BASE_DIR / "reports"
ASSETS_DIR = BASE_DIR / "assets"

# Create directories if they don't exist
for d in [DATA_DIR, MODEL_DIR, REPORTS_DIR, ASSETS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─── Model Settings ──────────────────────────────────────────────────────────
DISTILBERT_MODEL_NAME = "distilbert-base-uncased"
MAX_SEQUENCE_LENGTH = 256
BATCH_SIZE = 16
LEARNING_RATE = 2e-5
NUM_EPOCHS = 5
WARMUP_STEPS = 100
WEIGHT_DECAY = 0.01

# ─── Threat Classes ──────────────────────────────────────────────────────────
THREAT_CLASSES = [
    "Benign",
    "Phishing",
    "Malware",
    "Ransomware",
    "DDoS",
    "SQL Injection",
]

THREAT_LABEL2ID = {label: idx for idx, label in enumerate(THREAT_CLASSES)}
THREAT_ID2LABEL = {idx: label for idx, label in enumerate(THREAT_CLASSES)}
NUM_LABELS = len(THREAT_CLASSES)

# ─── Severity Levels ─────────────────────────────────────────────────────────
SEVERITY_LEVELS = {
    "Benign":        {"level": "None",     "score": 0,  "color": "#00C853"},
    "Phishing":      {"level": "High",     "score": 75, "color": "#FF6D00"},
    "Malware":       {"level": "Critical", "score": 95, "color": "#D50000"},
    "Ransomware":    {"level": "Critical", "score": 100,"color": "#B71C1C"},
    "DDoS":          {"level": "High",     "score": 80, "color": "#FF6D00"},
    "SQL Injection": {"level": "High",     "score": 85, "color": "#E65100"},
}

# ─── Cybersecurity Keywords ───────────────────────────────────────────────────
CYBER_KEYWORDS = {
    "phishing": [
        # Account actions & urgency
        "account locked", "account suspended", "account blocked", "account disabled",
        "account temporarily", "temporarily locked", "temporarily suspended",
        "verify your account", "verify your identity", "verify your email",
        "confirm your account", "confirm your identity", "confirm your details",
        "restore access", "restore your account", "regain access", "reactivate",
        "click the link", "click the secure link", "click here", "click below",
        "click to verify", "click to confirm", "follow this link",
        "secure link", "secure portal", "secure page",
        "24 hours", "48 hours", "within hours", "immediately", "urgent",
        "action required", "immediate action", "response required",
        # Credential theft
        "phish", "credential", "login page", "fake website",
        "password reset", "reset your password", "update your password",
        "enter your password", "enter your credentials", "enter your details",
        "social engineering", "spear phishing",
        # Brand impersonation
        "paypal", "netflix", "amazon", "apple id", "microsoft account",
        "google account", "bank account", "chase bank", "wells fargo",
        "your account will be", "your subscription", "your membership",
        # Deception signals
        "deceptive", "impersonation", "spoofing", "suspicious link",
        "suspicious activity", "unusual activity", "irregular activity",
        "we detected", "we noticed", "we found", "we have detected",
        "gift card", "you have won", "claim your", "free prize",
        "irs", "tax refund", "lottery", "inheritance",
    ],
    "malware": [
        "malware", "virus", "trojan", "worm", "spyware", "adware",
        "rootkit", "backdoor", "keylogger", "botnet", "payload",
        "executable", "dropper", "loader", "command and control",
        "c2 server", "lateral movement", "persistence", "remote access trojan",
        "rat ", "apt ", "process hollowing", "dll injection", "code injection",
        "polymorphic", "obfuscated", "evasion", "sandbox evasion",
        "memory resident", "fileless", "living off the land",
    ],
    "ransomware": [
        "ransomware", "ransom", "decrypt", "decryption key", "recovery key",
        "files encrypted", "file locked", "encrypted files", "your files",
        "bitcoin", "monero", "cryptocurrency payment", "pay ransom",
        "cryptolocker", "wannacry", "ryuk", "lockbit", "darkside", "revil",
        "blackcat", "conti", "hive", "double extortion", "data exfiltration",
        "payment deadline", "tor browser", "dark web", "onion",
    ],
    "ddos": [
        "ddos", "denial of service", "dos attack", "syn flood", "udp flood",
        "http flood", "icmp flood", "amplification attack", "reflection attack",
        "bandwidth exhaustion", "traffic spike", "network overload",
        "botnet attack", "layer 7", "volumetric", "scrubbing",
        "packet storm", "connection exhaustion", "slowloris",
        "memcached", "ntp amplification", "dns amplification",
    ],
    "sql_injection": [
        "sql injection", "sqli", "union select", "drop table", "or 1=1",
        "blind sql", "database dump", "stored procedure", "xss",
        "sqlmap", "error-based", "time-based blind", "out-of-band",
        "boolean-based", "stacked queries", "webshell", "xp_cmdshell",
        "load_file", "into outfile", "information_schema",
    ],
    "benign": [
        "security patch", "patch applied", "security update", "advisory",
        "best practice", "firewall rule", "vpn access", "compliance check",
        "security audit", "security policy", "no threats detected",
        "scan completed", "penetration test", "pen test report",
    ],
}

# ─── NER Patterns ────────────────────────────────────────────────────────────
IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
URL_PATTERN = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
CVE_PATTERN = r'CVE-\d{4}-\d{4,7}'
HASH_PATTERN = r'\b[0-9a-fA-F]{32,64}\b'

# ─── Dashboard Settings ───────────────────────────────────────────────────────
APP_TITLE = "CyberGuard AI — Threat Intelligence Platform"
APP_ICON = "🛡️"
APP_LAYOUT = "wide"

# ─── Color Palette ───────────────────────────────────────────────────────────
COLORS = {
    "primary":    "#0D47A1",
    "secondary":  "#1565C0",
    "accent":     "#00E5FF",
    "danger":     "#D50000",
    "warning":    "#FF6D00",
    "success":    "#00C853",
    "background": "#0A0E1A",
    "card":       "#111827",
    "text":       "#E2E8F0",
}
