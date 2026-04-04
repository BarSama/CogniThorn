#!/usr/bin/env python3
"""
Download the ONNX model for CogniThorn WAF inference.

--- Model choices (set ONNX_MODEL_REPO env var to switch) ---

1. distilbert-base-uncased (default — generic, untrained for WAF)
   Repo: distilbert/distilbert-base-uncased
   Pros: small (66M params), fast inference (~15ms CPU), well-tested
   Cons: NOT trained on attack patterns — needs fine-tuning before use
   Use when: you plan to fine-tune with scripts/fine_tune_model.py

2. jackaduma/SecBERT (recommended starting point)
   Repo: jackaduma/SecBERT
   Pros: pre-trained on security text (NVD, exploit-db, security blogs)
         understands security terminology better than vanilla DistilBERT
   Cons: larger (110M params), still needs WAF-specific fine-tuning
   Use when: you want a model that already understands "SQL injection" semantics

3. huggingface.co/msmarco-distilbert-base-v4 (semantic similarity)
   Not recommended for WAF — trained for search, not classification

--- Production recommendation ---
Run scripts/fine_tune_model.py with the labeled dataset in tests/data/payloads.json
then benchmark with scripts/benchmark_model.py. Use whichever model gets the
highest F1 score on your actual traffic mix.

--- After download ---
Restart workers: docker compose restart waf-worker
Benchmark: docker compose exec waf-worker python scripts/benchmark_model.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_REPO = os.environ.get(
    "ONNX_MODEL_REPO",
    "distilbert/distilbert-base-uncased",
)


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Try to use optimum to export to ONNX; fall back to downloading a pre-exported one
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer

        print(f"Downloading and exporting {MODEL_REPO} to ONNX...")
        model = ORTModelForSequenceClassification.from_pretrained(MODEL_REPO, export=True)
        tokenizer = AutoTokenizer.from_pretrained(MODEL_REPO)

        model.save_pretrained(MODEL_DIR)
        tokenizer.save_pretrained(MODEL_DIR)
        print(f"Model saved to {MODEL_DIR}")
    except ImportError:
        print("optimum not installed. Attempting direct HuggingFace Hub download...")
        try:
            from huggingface_hub import snapshot_download

            snapshot_download(
                repo_id=MODEL_REPO,
                local_dir=MODEL_DIR,
                ignore_patterns=["*.msgpack", "*.h5", "flax_*"],
            )
            print(f"Model files downloaded to {MODEL_DIR}")
            print("NOTE: You may need to convert to ONNX format manually.")
        except Exception as e:
            print(f"Download failed: {e}")
            print(f"Please manually place model.onnx and tokenizer.json in {MODEL_DIR}")
            sys.exit(1)


if __name__ == "__main__":
    main()
