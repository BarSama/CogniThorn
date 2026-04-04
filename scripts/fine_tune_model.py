#!/usr/bin/env python3
"""
Fine-tune DistilBERT on the CogniThorn payload dataset and export to ONNX.

--- Why fine-tuning is necessary ---
The base DistilBERT model was trained on general English text (Wikipedia, books).
It has no understanding of what "OR '1'='1'" means in a security context.
Fine-tuning on labeled attack/clean payloads teaches the model the patterns
that matter for WAF detection — after fine-tuning, the same model architecture
becomes a specialist instead of a generalist.

--- How fine-tuning works ---
1. Start with pre-trained DistilBERT (it already understands English grammar
   and token relationships — this took weeks of GPU time to learn)
2. Add a classification head: two output neurons (clean=0, attack=1)
3. Train only the top layers on our labeled data — the lower layers already
   know language, we just teach the top what "attack patterns" look like
4. Export the result to ONNX format so ONNX Runtime can serve it

This is called "transfer learning" — reusing learned knowledge for a new task.

--- Requirements ---
  pip install transformers datasets optimum[onnxruntime] torch scikit-learn

  GPU recommended (NVIDIA with CUDA) but not required.
  CPU fine-tuning takes ~10 minutes for 3 epochs on the 65-sample dataset.
  GPU fine-tuning takes ~30 seconds.

--- How to run ---
  # From CogniThorn root, with model dependencies available:
  python scripts/fine_tune_model.py

  # Custom epochs and batch size:
  FINETUNE_EPOCHS=5 FINETUNE_BATCH_SIZE=8 python scripts/fine_tune_model.py

--- Output ---
  models/model.onnx       — the fine-tuned model ready for ONNX Runtime
  models/tokenizer.json   — matching tokenizer (don't change this between model versions)

--- After fine-tuning ---
  Restart the WAF workers to pick up the new model:
    docker compose restart waf-worker

  Then benchmark to measure improvement:
    python scripts/benchmark_model.py
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

MODEL_DIR = Path(__file__).parent.parent / "models"
PAYLOAD_PATH = Path(__file__).parent.parent / "tests" / "data" / "payloads.json"
BASE_MODEL = os.getenv("FINETUNE_BASE_MODEL", "distilbert-base-uncased")
EPOCHS = int(os.getenv("FINETUNE_EPOCHS", "3"))
BATCH_SIZE = int(os.getenv("FINETUNE_BATCH_SIZE", "8"))
MAX_LENGTH = 512


def load_dataset():
    """Load payloads.json and split into train/eval (80/20)."""
    with open(PAYLOAD_PATH) as f:
        payloads = json.load(f)

    from data_plane.detection.tokenizer_utils import build_input_text

    texts = [
        build_input_text(p["method"], p["path"], p.get("query", ""), p.get("body", ""))
        for p in payloads
    ]
    labels = [p["label"] for p in payloads]

    # Stratified split — keep attack/clean ratio in both splits
    from sklearn.model_selection import train_test_split
    train_texts, eval_texts, train_labels, eval_labels = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    print(f"Train: {len(train_texts)} samples  Eval: {len(eval_texts)} samples")
    return train_texts, eval_texts, train_labels, eval_labels


def tokenize(tokenizer, texts: list[str], labels: list[int]):
    """Tokenize texts into a HuggingFace Dataset."""
    from datasets import Dataset

    encoding = tokenizer(
        texts,
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors=None,
    )
    return Dataset.from_dict({
        "input_ids": encoding["input_ids"],
        "attention_mask": encoding["attention_mask"],
        "labels": labels,
    })


def main():
    print("CogniThorn Model Fine-Tuner")
    print(f"Base model : {BASE_MODEL}")
    print(f"Epochs     : {EPOCHS}")
    print(f"Batch size : {BATCH_SIZE}")
    print(f"Output dir : {MODEL_DIR}")
    print()

    # Check dependencies
    try:
        import torch
        import transformers
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
        import datasets
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"PyTorch {torch.__version__}  |  Device: {device}")
        if device == "cpu":
            print("  (GPU not available — training on CPU, expect ~10 minutes)")
        print()
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with: pip install transformers datasets torch scikit-learn optimum[onnxruntime]")
        sys.exit(1)

    # Load tokenizer (from base model or local if already downloaded)
    print("Loading tokenizer...")
    try:
        tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    except Exception as e:
        print(f"Failed to load tokenizer: {e}")
        sys.exit(1)

    # Load and tokenize dataset
    print("Loading payload dataset...")
    train_texts, eval_texts, train_labels, eval_labels = load_dataset()
    train_ds = tokenize(tokenizer, train_texts, train_labels)
    eval_ds  = tokenize(tokenizer, eval_texts, eval_labels)

    # Load base model with classification head (2 classes: clean=0, attack=1)
    print(f"\nLoading base model {BASE_MODEL}...")
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label={0: "clean", 1: "attack"},
        label2id={"clean": 0, "attack": 1},
    )

    # Training configuration
    # Explanation of key hyperparameters for learners:
    #   learning_rate: how fast to update weights — too high = unstable, too low = slow
    #   warmup_steps: gradually increase LR for first N steps — prevents early instability
    #   weight_decay: L2 regularization — penalizes large weights to prevent overfitting
    #   eval_strategy: compute metrics on the eval set every epoch so we can track progress
    training_args = TrainingArguments(
        output_dir=str(MODEL_DIR / "fine_tune_checkpoints"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        learning_rate=2e-5,
        warmup_steps=10,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=10,
        report_to="none",  # disable wandb/tensorboard
    )

    # Custom metric computation for trainer
    def compute_metrics(eval_pred):
        import numpy as np
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        tp = int(((preds == 1) & (labels == 1)).sum())
        fp = int(((preds == 1) & (labels == 0)).sum())
        fn = int(((preds == 0) & (labels == 1)).sum())
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        return {"precision": precision, "recall": recall, "f1": f1}

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        compute_metrics=compute_metrics,
    )

    print("\nStarting training...")
    trainer.train()

    # Evaluate final model
    metrics = trainer.evaluate()
    print(f"\nFinal eval — F1: {metrics.get('eval_f1', 'N/A'):.3f}  "
          f"Precision: {metrics.get('eval_precision', 'N/A'):.3f}  "
          f"Recall: {metrics.get('eval_recall', 'N/A'):.3f}")

    # Export to ONNX
    print("\nExporting to ONNX...")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        ort_model = ORTModelForSequenceClassification.from_pretrained(
            training_args.output_dir, export=True
        )
        ort_model.save_pretrained(str(MODEL_DIR))
        tokenizer.save_pretrained(str(MODEL_DIR))
        print(f"Model saved to {MODEL_DIR}/model.onnx")
    except ImportError:
        # Fallback: save PyTorch model and note the extra step
        model.save_pretrained(str(MODEL_DIR / "pytorch"))
        tokenizer.save_pretrained(str(MODEL_DIR / "pytorch"))
        print(f"PyTorch model saved to {MODEL_DIR}/pytorch/")
        print("ONNX export requires `optimum`. Install with:")
        print("  pip install optimum[onnxruntime]")
        print("Then run:")
        print(f"  optimum-cli export onnx --model {MODEL_DIR}/pytorch/ {MODEL_DIR}/")

    print("\nDone! Restart WAF workers to load the new model:")
    print("  docker compose restart waf-worker")
    print("Then benchmark:")
    print("  docker compose exec waf-worker python scripts/benchmark_model.py")


if __name__ == "__main__":
    main()
