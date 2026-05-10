"""
DistilBERT-based multi-class Cyber Threat Classifier.
Handles training, evaluation, saving, loading, and inference.
"""

import os
import json
import torch
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments,
    EarlyStoppingCallback,
)
from torch.utils.data import Dataset
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report, confusion_matrix,
)

from config.settings import (
    DISTILBERT_MODEL_NAME, MAX_SEQUENCE_LENGTH, BATCH_SIZE,
    LEARNING_RATE, NUM_EPOCHS, WARMUP_STEPS, WEIGHT_DECAY,
    MODEL_DIR, THREAT_LABEL2ID, THREAT_ID2LABEL, NUM_LABELS, THREAT_CLASSES,
)


# ─── Dataset Wrapper ──────────────────────────────────────────────────────────

class ThreatDataset(Dataset):
    def __init__(self, encodings: dict, labels: List[int]):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[idx], dtype=torch.long)
        return item


# ─── Metrics ──────────────────────────────────────────────────────────────────

def compute_metrics(eval_pred) -> Dict[str, float]:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1_macro": f1_score(labels, preds, average="macro"),
        "f1_weighted": f1_score(labels, preds, average="weighted"),
    }


# ─── Classifier ───────────────────────────────────────────────────────────────

class ThreatClassifier:
    """DistilBERT fine-tuned for cyber threat multi-class classification."""

    def __init__(self, model_path: Optional[str] = None):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_path = model_path or str(MODEL_DIR)
        self.tokenizer: Optional[DistilBertTokenizer] = None
        self.model: Optional[DistilBertForSequenceClassification] = None

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, df: pd.DataFrame, text_col: str = "text", label_col: str = "label") -> Dict:
        """Fine-tune DistilBERT on the provided dataframe."""
        print(f"[INFO] Training on {len(df)} samples | Device: {self.device}")

        # Encode labels
        df["label_id"] = df[label_col].map(THREAT_LABEL2ID)
        df = df.dropna(subset=["label_id"])

        texts = df[text_col].tolist()
        labels = df["label_id"].astype(int).tolist()

        X_train, X_val, y_train, y_val = train_test_split(
            texts, labels, test_size=0.15, stratify=labels, random_state=42
        )

        # Tokenizer
        self.tokenizer = DistilBertTokenizer.from_pretrained(DISTILBERT_MODEL_NAME)

        enc_train = self.tokenizer(
            X_train, truncation=True, padding=True, max_length=MAX_SEQUENCE_LENGTH
        )
        enc_val = self.tokenizer(
            X_val, truncation=True, padding=True, max_length=MAX_SEQUENCE_LENGTH
        )

        train_ds = ThreatDataset(enc_train, y_train)
        val_ds   = ThreatDataset(enc_val,   y_val)

        # Model
        self.model = DistilBertForSequenceClassification.from_pretrained(
            DISTILBERT_MODEL_NAME,
            num_labels=NUM_LABELS,
            id2label=THREAT_ID2LABEL,
            label2id=THREAT_LABEL2ID,
        ).to(self.device)

        # Training args
        args = TrainingArguments(
            output_dir=str(MODEL_DIR / "checkpoints"),
            num_train_epochs=NUM_EPOCHS,
            per_device_train_batch_size=BATCH_SIZE,
            per_device_eval_batch_size=BATCH_SIZE,
            learning_rate=LEARNING_RATE,
            warmup_steps=WARMUP_STEPS,
            weight_decay=WEIGHT_DECAY,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="f1_macro",
            greater_is_better=True,
            logging_dir=str(MODEL_DIR / "logs"),
            logging_steps=50,
            report_to="none",
            fp16=torch.cuda.is_available(),
        )

        trainer = Trainer(
            model=self.model,
            args=args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            compute_metrics=compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
        )

        trainer.train()
        eval_results = trainer.evaluate()

        # Save
        self.save_model()
        return eval_results

    # ── Save / Load ───────────────────────────────────────────────────────────

    def save_model(self):
        """Persist model and tokenizer to MODEL_DIR."""
        save_path = Path(self.model_path)
        save_path.mkdir(parents=True, exist_ok=True)
        self.model.save_pretrained(str(save_path))
        self.tokenizer.save_pretrained(str(save_path))

        meta = {"num_labels": NUM_LABELS, "label2id": THREAT_LABEL2ID, "id2label": THREAT_ID2LABEL}
        with open(save_path / "meta.json", "w") as f:
            json.dump(meta, f, indent=2)
        print(f"[✓] Model saved → {save_path}")

    def load_model(self) -> bool:
        """Load model from disk. Returns True if successful."""
        model_path = Path(self.model_path)
        if not (model_path / "config.json").exists():
            return False
        try:
            self.tokenizer = DistilBertTokenizer.from_pretrained(str(model_path))
            self.model = DistilBertForSequenceClassification.from_pretrained(
                str(model_path)
            ).to(self.device)
            self.model.eval()
            print(f"[✓] Model loaded from {model_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Could not load model: {e}")
            return False

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, text: str) -> Dict:
        """
        Run inference on a single text string.

        Returns:
            {
              "predicted_label": str,
              "predicted_id":    int,
              "confidence":      float,
              "probabilities":   Dict[str, float],
            }
        """
        if self.model is None or self.tokenizer is None:
            raise RuntimeError("Model not loaded. Call load_model() or train() first.")

        self.model.eval()
        enc = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=MAX_SEQUENCE_LENGTH,
        ).to(self.device)

        with torch.no_grad():
            logits = self.model(**enc).logits

        probs = torch.softmax(logits, dim=-1).squeeze().cpu().numpy()
        pred_id = int(np.argmax(probs))
        pred_label = THREAT_ID2LABEL[pred_id]

        return {
            "predicted_label": pred_label,
            "predicted_id":    pred_id,
            "confidence":      float(probs[pred_id]),
            "probabilities":   {THREAT_ID2LABEL[i]: float(p) for i, p in enumerate(probs)},
        }

    def predict_batch(self, texts: List[str]) -> List[Dict]:
        return [self.predict(t) for t in texts]

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate_on_df(self, df: pd.DataFrame, text_col: str = "text", label_col: str = "label") -> Dict:
        """Return full classification report on a test dataframe."""
        preds = [self.predict(t)["predicted_label"] for t in df[text_col]]
        true  = df[label_col].tolist()
        report = classification_report(true, preds, output_dict=True)
        cm     = confusion_matrix(true, preds, labels=THREAT_CLASSES)
        return {"classification_report": report, "confusion_matrix": cm.tolist()}
