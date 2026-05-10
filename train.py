"""
Training script — loads real dataset (JSONL/CSV) or synthetic fallback,
then fine-tunes DistilBERT.

Usage:
    python train.py              # auto-detect real data
    python train.py --synthetic  # force synthetic data
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from data.data_loader import load_dataset
from models.classifier import ThreatClassifier
from nlp.preprocessor import full_preprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--synthetic", action="store_true",
                        help="Force use of synthetic dataset")
    parser.add_argument("--epochs", type=int, default=None)
    args = parser.parse_args()

    print("=" * 60)
    print("  CyberGuard AI — DistilBERT Training Pipeline")
    print("=" * 60)

    # 1. Load data
    print("\n[1/3] Loading dataset...")
    df = load_dataset(prefer_real=not args.synthetic)
    print(f"      Total samples: {len(df):,}")

    # 2. Preprocess
    print("\n[2/3] Preprocessing text...")
    df = df.copy()
    df["text"] = df["text"].astype(str).apply(full_preprocess)
    df = df[df["text"].str.strip().ne("")]

    # 3. Train
    print("\n[3/3] Fine-tuning DistilBERT...")
    clf = ThreatClassifier()

    if args.epochs:
        from config import settings as cfg
        cfg.NUM_EPOCHS = args.epochs

    results = clf.train(df)
    print(f"\n✅ Training complete!")
    print(f"   Eval results: {results}")
    print("\n🚀 Launch the dashboard with:  streamlit run app.py")


if __name__ == "__main__":
    main()
