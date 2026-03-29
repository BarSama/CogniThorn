#!/usr/bin/env python3
"""
Download the DistilBERT ONNX model fine-tuned for SQL injection / XSS detection.
Uses the 'cybersectony/phishing-email-detection-distilbert_v2.4.1' model as a
placeholder; in production replace with a model fine-tuned on WAF attack payloads.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_REPO = os.environ.get(
    "ONNX_MODEL_REPO",
    "distilbert/distilbert-base-uncased",  # replace with fine-tuned WAF model
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
