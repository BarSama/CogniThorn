# CogniThorn ONNX Model

This directory holds the ONNX model and tokenizer used by the WAF workers.

## Download

Run the download script from the project root:

```bash
python scripts/download_model.py
```

Or, if running inside Docker:

```bash
docker compose run --rm waf-worker python scripts/download_model.py
```

## What Model Is Used?

The default model is `distilbert-base-uncased` exported to ONNX format via
the `optimum` library. For production use, replace it with a model fine-tuned
on a dataset of SQLi, XSS, and other injection payloads.

## Required Files

After download, this directory should contain:
- `model.onnx` — the ONNX model weights
- `tokenizer.json` — the fast tokenizer config
- `tokenizer_config.json`
- `vocab.txt`

## Custom Model

Set `ONNX_MODEL_REPO=your-org/your-model` in `.env` before running the download
script to use a different HuggingFace model.
