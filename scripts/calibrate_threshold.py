#!/usr/bin/env python3
"""
Threshold calibration — find the optimal sensitivity threshold for your model.

--- Why calibration matters ---
The default threshold of 0.7 is a guess. Your actual optimal value depends on:
  1. What model you're running (generic DistilBERT vs a fine-tuned WAF model)
  2. Your traffic mix (how much of your traffic is "tricky clean" vs obvious attacks)
  3. Your tolerance for false positives vs missed attacks

This script sweeps threshold values from 0.05 to 0.95 and shows you the
precision/recall trade-off at each step. You then choose based on your priority:
  - High recall (catch everything): lower the threshold
  - High precision (fewer false positives): raise the threshold
  - Balanced (F1-optimal): pick the row with the highest F1

--- The precision-recall trade-off ---
These two metrics always move in opposite directions:
  Lowering threshold → catch more attacks (higher recall) BUT also block more
                       legitimate requests (lower precision)
  Raising threshold  → fewer false positives (higher precision) BUT miss more
                       attacks (lower recall)

There is no free lunch. You must decide what's more important for your use case.
For a login page: recall is critical (you really don't want to miss an SQLi).
For a read-only public API: precision is more important (false positives = angry users).

--- How to run ---
  docker compose exec waf-worker python scripts/calibrate_threshold.py

  # Save output to file:
  docker compose exec waf-worker python scripts/calibrate_threshold.py > calibration.txt
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def load_and_score_all(session, tokenizer) -> list[tuple[float, int, str]]:
    """
    Score all payloads once, return (score, true_label, attack_type) tuples.
    We score once and sweep thresholds in memory — this is much faster than
    re-running inference for each threshold value.
    """
    from data_plane.detection.tokenizer_utils import build_input_text
    import numpy as np

    payload_path = Path(__file__).parent.parent / "tests" / "data" / "payloads.json"
    with open(payload_path) as f:
        payloads = json.load(f)

    results = []
    for p in payloads:
        text = build_input_text(
            p["method"], p["path"], p.get("query", ""), p.get("body", "")
        )
        encoding = tokenizer.encode(text)
        inputs = {
            "input_ids": np.array([encoding.ids], dtype=np.int64),
            "attention_mask": np.array([encoding.attention_mask], dtype=np.int64),
        }
        outputs = session.run(None, inputs)
        logits = outputs[0][0]
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        score = float(probs[1]) if len(probs) > 1 else float(probs[0])
        results.append((score, p["label"], p["attack_type"]))

    return results


def compute_metrics(scores: list[tuple[float, int, str]], threshold: float) -> dict:
    """Compute TP/FP/TN/FN and derived metrics at a given threshold."""
    tp = fp = tn = fn = 0
    for score, true_label, _ in scores:
        blocked = score >= threshold
        is_attack = true_label == 1
        if is_attack and blocked:
            tp += 1
        elif is_attack and not blocked:
            fn += 1
        elif not is_attack and blocked:
            fp += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0  # no blocks = perfect precision
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0
    return {
        "threshold": threshold,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def main():
    from shared.config.settings import settings

    print("CogniThorn Threshold Calibration")
    print(f"Model: {settings.onnx_model_path}")
    print(f"{'─' * 75}")

    try:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        session = ort.InferenceSession(settings.onnx_model_path, sess_options=opts)

        tokenizer_path = str(Path(settings.onnx_model_path).parent / "tokenizer.json")
        tokenizer = Tokenizer.from_file(tokenizer_path)
        tokenizer.enable_padding(pad_id=0, pad_token="[PAD]", length=512)
        tokenizer.enable_truncation(max_length=512)
    except Exception as e:
        print(f"ERROR: Could not load model: {e}")
        sys.exit(1)

    print("Scoring all payloads once...")
    all_scores = load_and_score_all(session, tokenizer)
    n_attacks = sum(1 for _, label, _ in all_scores if label == 1)
    n_clean   = sum(1 for _, label, _ in all_scores if label == 0)
    print(f"Dataset: {len(all_scores)} samples ({n_attacks} attacks, {n_clean} clean)\n")

    # Sweep thresholds
    thresholds = [round(t * 0.05, 2) for t in range(1, 20)]  # 0.05 to 0.95
    rows = [compute_metrics(all_scores, t) for t in thresholds]

    # Find best F1
    best = max(rows, key=lambda r: r["f1"])
    current = settings.sensitivity_threshold

    # ── Table ────────────────────────────────────────────────────────────────
    print(f"  {'Threshold':>9}  {'Precision':>9}  {'Recall':>7}  {'F1':>6}  {'Accuracy':>9}  {'TP':>4}  {'FP':>4}  {'FN':>4}  {'TN':>4}")
    print(f"  {'─' * 73}")

    for r in rows:
        marker = ""
        if r["threshold"] == best["threshold"]:
            marker = "  ← BEST F1"
        if abs(r["threshold"] - current) < 0.001:
            marker += "  ← CURRENT"
        print(
            f"  {r['threshold']:>9.2f}  {r['precision']:>9.3f}  {r['recall']:>7.3f}"
            f"  {r['f1']:>6.3f}  {r['accuracy']:>9.3f}"
            f"  {r['tp']:>4}  {r['fp']:>4}  {r['fn']:>4}  {r['tn']:>4}{marker}"
        )

    # ── Summary ──────────────────────────────────────────────────────────────
    current_metrics = next((r for r in rows if abs(r["threshold"] - current) < 0.001), None)
    print(f"\n{'─' * 75}")
    print(f"  Best F1 threshold : {best['threshold']:.2f}  (F1={best['f1']:.3f})")
    if current_metrics:
        print(f"  Current threshold : {current:.2f}  (F1={current_metrics['f1']:.3f})")
        delta_f1 = best["f1"] - current_metrics["f1"]
        if delta_f1 > 0.02:
            print(f"\n  RECOMMENDATION: Change threshold from {current:.2f} → {best['threshold']:.2f}")
            print(f"  This would improve F1 by {delta_f1:.3f}")
            print(f"  Update via: PUT /api/settings {{\"sensitivity_threshold\": \"{best['threshold']:.2f}\"}}")
        else:
            print(f"\n  RECOMMENDATION: Current threshold {current:.2f} is near-optimal (delta F1 < 0.02).")
    print()

    # ── Score distribution ───────────────────────────────────────────────────
    print("  Score distribution:")
    attack_scores = sorted([s for s, label, _ in all_scores if label == 1])
    clean_scores  = sorted([s for s, label, _ in all_scores if label == 0])
    a_median = attack_scores[len(attack_scores) // 2]
    c_median = clean_scores[len(clean_scores) // 2]
    a_min, a_max = min(attack_scores), max(attack_scores)
    c_min, c_max = min(clean_scores), max(clean_scores)
    print(f"    Attacks : min={a_min:.3f}  median={a_median:.3f}  max={a_max:.3f}")
    print(f"    Clean   : min={c_min:.3f}  median={c_median:.3f}  max={c_max:.3f}")

    overlap = sum(1 for s in attack_scores if s < best["threshold"])
    if overlap:
        print(f"\n  WARNING: {overlap} attack payload(s) score below the best threshold.")
        print("  Consider fine-tuning the model: python scripts/fine_tune_model.py")
    print()


if __name__ == "__main__":
    main()
