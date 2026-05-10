"""
NLP Preprocessing Pipeline — text cleaning, tokenization, keyword extraction,
Named Entity Recognition (NER) for IPs, URLs, emails, CVEs, and file hashes.
"""

import re
import string
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from typing import Dict, List, Tuple

from config.settings import (
    IP_PATTERN, URL_PATTERN, EMAIL_PATTERN, CVE_PATTERN, HASH_PATTERN,
    CYBER_KEYWORDS,
)

# Download NLTK resources on first import
for resource in ["punkt", "stopwords", "wordnet", "averaged_perceptron_tagger", "punkt_tab"]:
    try:
        nltk.download(resource, quiet=True)
    except Exception:
        pass

_STOP_WORDS = set(stopwords.words("english"))
_LEMMATIZER = WordNetLemmatizer()

# Cybersecurity stop-words to KEEP (overrides generic stop list)
CYBER_PRESERVE = {
    "not", "no", "nor", "never", "attack", "inject", "drop", "select",
    "union", "or", "and", "exec",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Text Cleaning
# ─────────────────────────────────────────────────────────────────────────────

def clean_text(text: str, preserve_entities: bool = False) -> str:
    """
    Clean raw text for NLP processing.

    Args:
        text: Raw input string.
        preserve_entities: If True, replace URLs/IPs with placeholder tokens
                           instead of removing them.
    Returns:
        Cleaned string.
    """
    if not isinstance(text, str):
        text = str(text)

    # Optionally replace entities with tokens before lowercasing
    if preserve_entities:
        text = re.sub(URL_PATTERN, " URL_TOKEN ", text)
        text = re.sub(IP_PATTERN, " IP_TOKEN ", text)
        text = re.sub(EMAIL_PATTERN, " EMAIL_TOKEN ", text)
        text = re.sub(CVE_PATTERN, " CVE_TOKEN ", text)
        text = re.sub(HASH_PATTERN, " HASH_TOKEN ", text)

    text = text.lower()

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Remove special chars except alphanumeric and basic punctuation
    text = re.sub(r"[^\w\s\.\-\_\@]", " ", text)

    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def tokenize(text: str, remove_stopwords: bool = True) -> List[str]:
    """Tokenize and optionally remove stop-words."""
    tokens = word_tokenize(text)
    tokens = [t for t in tokens if t not in string.punctuation]
    if remove_stopwords:
        tokens = [
            t for t in tokens
            if t not in _STOP_WORDS or t in CYBER_PRESERVE
        ]
    return tokens


def lemmatize_tokens(tokens: List[str]) -> List[str]:
    return [_LEMMATIZER.lemmatize(t) for t in tokens]


def full_preprocess(text: str) -> str:
    """End-to-end preprocessing: clean → tokenize → lemmatize → rejoin."""
    cleaned = clean_text(text)
    tokens = tokenize(cleaned)
    lemmas = lemmatize_tokens(tokens)
    return " ".join(lemmas)


# ─────────────────────────────────────────────────────────────────────────────
#  Named Entity Recognition (regex-based)
# ─────────────────────────────────────────────────────────────────────────────

def extract_entities(text: str) -> Dict[str, List[str]]:
    """
    Extract cybersecurity-relevant named entities from raw text.

    Returns:
        Dict with keys: urls, ips, emails, cves, hashes
    """
    return {
        "urls":   list(set(re.findall(URL_PATTERN, text))),
        "ips":    list(set(re.findall(IP_PATTERN, text))),
        "emails": list(set(re.findall(EMAIL_PATTERN, text))),
        "cves":   list(set(re.findall(CVE_PATTERN, text))),
        "hashes": list(set(re.findall(HASH_PATTERN, text))),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Keyword Extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_keywords(text: str) -> Dict[str, List[str]]:
    """
    Match text against the cybersecurity keyword dictionary.

    Returns:
        Dict mapping each threat category to matched keywords found.
    """
    text_lower = text.lower()
    matches: Dict[str, List[str]] = {}

    for category, kw_list in CYBER_KEYWORDS.items():
        found = [kw for kw in kw_list if kw in text_lower]
        if found:
            matches[category] = found

    return matches


def get_top_keywords(text: str, top_n: int = 10) -> List[Tuple[str, str]]:
    """
    Return a flat list of (keyword, category) tuples sorted by category priority.
    """
    all_kws = extract_keywords(text)
    flat = []
    for cat, kws in all_kws.items():
        for kw in kws:
            flat.append((kw, cat))

    # Deduplicate and limit
    seen = set()
    result = []
    for kw, cat in flat:
        if kw not in seen:
            seen.add(kw)
            result.append((kw, cat))
        if len(result) >= top_n:
            break
    return result


# ─────────────────────────────────────────────────────────────────────────────
#  Quick Test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample = (
        "Urgent: Your PayPal account will be suspended. Click http://paypal-fake.xyz/login "
        "to verify. Contact support@secure-bank.net. CVE-2023-44487 detected on 192.168.1.100"
    )
    print("Cleaned:", clean_text(sample))
    print("Entities:", extract_entities(sample))
    print("Keywords:", extract_keywords(sample))
    print("Top keywords:", get_top_keywords(sample))
