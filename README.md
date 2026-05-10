# 🛡️ CyberGuard AI — Cyber Threat Intelligence System

An **AI-powered, NLP-based Cyber Threat Intelligence System** built with
DistilBERT, Streamlit, and Python. Detects and classifies 6 threat types
from raw text with explainable AI, NER, keyword extraction, and PDF reports.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
cd cyber_threat_intel
pip install -r requirements.txt
```

### 2. Launch the app (no training needed — uses rule-based engine instantly)
```bash
streamlit run app.py
```

### 3. (Optional) Train DistilBERT for higher accuracy
```bash
python train.py
streamlit run app.py   # now uses the fine-tuned model
```

---

## 📁 Project Structure

```
cyber_threat_intel/
├── app.py                      # Main Streamlit dashboard
├── train.py                    # DistilBERT training pipeline
├── requirements.txt
│
├── config/
│   └── settings.py             # Global config, constants, paths
│
├── data/
│   └── data_generator.py       # Synthetic dataset generator
│
├── nlp/
│   └── preprocessor.py         # Text cleaning, NER, keyword extraction
│
├── models/
│   ├── classifier.py           # DistilBERT fine-tune + inference
│   ├── rule_based.py           # Keyword-frequency fallback
│   └── saved/                  # Saved model weights (after training)
│
├── intelligence/
│   ├── engine.py               # Threat analysis orchestration
│   └── report_generator.py     # PDF / text report generator
│
├── ui/
│   └── components.py           # Reusable Streamlit UI components
│
├── reports/                    # Auto-saved PDF/text reports
└── assets/                     # Static assets
```

---

## 🎯 Detected Threat Types

| Threat | Severity | Description |
|---|---|---|
| ✅ Benign | None | Normal security communications |
| 🎣 Phishing | High | Credential harvesting, social engineering |
| 🦠 Malware | Critical | Trojans, RATs, spyware, botnets |
| 💰 Ransomware | Critical | File encryption, ransom demands |
| 💥 DDoS | High | Volumetric/application layer flood attacks |
| 💉 SQL Injection | High | Database query manipulation attacks |

---

## 🧠 System Architecture

```
Input Text
    │
    ▼
NLP Preprocessor ──► Text Cleaning, Tokenization, Lemmatization
    │
    ├──► Named Entity Recognition (IPs, URLs, Emails, CVEs, Hashes)
    │
    ├──► Keyword Extraction (per threat category)
    │
    ▼
Classifier
    ├── DistilBERT (if trained model exists)
    └── Rule-Based Fallback (always available)
    │
    ▼
Threat Intel Engine ──► Severity + Risk Score + XAI Reasoning
    │
    ▼
Streamlit Dashboard ──► Charts, Entity Tags, Recommendations
    │
    ▼
PDF Report Generator
```

---

## ⚡ Features

- 🔍 **Real-time analysis** — instant results as you type/submit
- 🧠 **DistilBERT** — transformer-based multi-class classification
- 🎯 **Confidence scoring** — probability distribution across all 6 classes
- 🔎 **NER** — extracts IPs, URLs, emails, CVEs, file hashes
- 🏷️ **Keyword extraction** — maps to threat categories
- 🧩 **Explainable AI** — human-readable reasoning for each prediction
- 📊 **Interactive charts** — gauge, donut, bar charts via Plotly
- 📄 **PDF reports** — downloadable threat intelligence reports
- 🕒 **Analysis history** — tracks all analyses in session
- ⚡ **Rule-based fallback** — works without GPU/training

---

## 📦 Requirements

- Python 3.9+
- 4GB RAM minimum (8GB recommended for training)
- GPU optional (CPU inference supported)
