#!/usr/bin/env python3
"""
Benchmark the ONNX WAF model against the labeled payload dataset.

--- What this script does ---
Loads tests/data/payloads.json (65 labeled samples), runs each one through
the ONNX model via the same code path the production WAF uses, then prints:
  - Per-attack-type breakdown: TP rate, FP rate
  - Overall: precision, recall, F1, accuracy
  - The samples the model got wrong (so you know where to improve)

--- How to run ---
  # From the CogniThorn root directory:
  docker compose exec waf-worker python scripts/benchmark_model.py

  # Or locally if you have the model downloaded:
  python scripts/benchmark_model.py

  # Test at a specific threshold (default reads from env SENSITIVITY_THRESHOLD):
  SENSITIVITY_THRESHOLD=0.5 python scripts/benchmark_model.py

--- Reading the output ---
  Precision = of all requests the WAF blocked, what % were real attacks?
    Low precision → high false positive rate → users getting blocked unfairly

  Recall = of all real attacks, what % did the WAF catch?
    Low recall → high miss rate → attacks slipping through

  F1 = harmonic mean of precision and recall (1.0 = perfect)
    The single best number to compare models or thresholds

  A good WAF target: Recall > 0.90, Precision > 0.85, F1 > 0.87
"""
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def load_payloads() -> list[dict]:
    payload_path = Path(__file__).parent.parent / "tests" / "data" / "payloads.json"
    with open(payload_path) as f:
        return json.load(f)


def score_payload(session, tokenizer, payload: dict, threshold: float) -> tuple[float, bool]:
    """Run one payload through the ONNX model. Returns (score, passed)."""
    from data_plane.detection.tokenizer_utils import build_input_text
    import numpy as np

    text = build_input_text(
        payload["method"],
        payload["path"],
        payload.get("query", ""),
        payload.get("body", ""),
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
    return score, score < threshold  # passed=True means not blocked


def main():
    from shared.config.settings import settings

    threshold = settings.sensitivity_threshold
    print(f"CogniThorn Model Benchmark")
    print(f"Model:     {settings.onnx_model_path}")
    print(f"Threshold: {threshold}")
    print(f"{'─' * 60}")

    # Load model
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
        print("Model loaded successfully.\n")
    except Exception as e:
        print(f"ERROR: Could not load model: {e}")
        print("Run: docker compose run --rm waf-worker python scripts/download_model.py")
        sys.exit(1)

    payloads = load_payloads()
    print(f"Evaluating {len(payloads)} payloads...\n")

    # Track results per attack type
    per_type: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "wrong": []})
    overall = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    latencies = []

    for p in payloads:
        t0 = time.perf_counter()
        score, passed = score_payload(session, tokenizer, p, threshold)
        latency_ms = (time.perf_counter() - t0) * 1000
        latencies.append(latency_ms)

        is_attack = p["label"] == 1
        blocked = not passed  # WAF blocked it if passed=False

        atype = p["attack_type"]

        if is_attack and blocked:       # Correct — caught an attack
            per_type[atype]["tp"] += 1
            overall["tp"] += 1
        elif is_attack and not blocked: # Missed attack (false negative)
            per_type[atype]["fn"] += 1
            overall["fn"] += 1
            per_type[atype]["wrong"].append({"score": round(score, 3), "note": p["note"]})
        elif not is_attack and blocked: # False positive — blocked legit traffic
            per_type[atype]["fp"] += 1
            overall["fp"] += 1
            per_type[atype]["wrong"].append({"score": round(score, 3), "note": p["note"]})
        else:                           # Correct — let clean traffic through
            per_type[atype]["tn"] += 1
            overall["tn"] += 1

    # ── Per-type breakdown ───────────────────────────────────────────────────
    print(f"{'Attack Type':<20} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Recall':>8} {'Precision':>10}")
    print(f"{'─' * 60}")

    for atype in sorted(per_type.keys()):
        d = per_type[atype]
        tp, fp, tn, fn = d["tp"], d["fp"], d["tn"], d["fn"]
        recall = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
        precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
        recall_s = f"{recall:.2f}" if recall == recall else "  N/A"
        precision_s = f"{precision:.2f}" if precision == precision else "      N/A"
        print(f"  {atype:<18} {tp:>4} {fp:>4} {tn:>4} {fn:>4} {recall_s:>8} {precision_s:>10}")

    # ── Overall metrics ──────────────────────────────────────────────────────
    tp, fp, tn, fn = overall["tp"], overall["fp"], overall["tn"], overall["fn"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / len(payloads)

    lat_sorted = sorted(latencies)
    p50 = lat_sorted[len(lat_sorted) // 2]
    p95 = lat_sorted[int(len(lat_sorted) * 0.95)]
    p99 = lat_sorted[int(len(lat_sorted) * 0.99)]

    print(f"\n{'─' * 60}")
    print(f"  Overall Results ({len(payloads)} samples, threshold={threshold})")
    print(f"{'─' * 60}")
    print(f"  Precision : {precision:.3f}  (of blocked requests, how many were real attacks?)")
    print(f"  Recall    : {recall:.3f}  (of all attacks, how many did we catch?)")
    print(f"  F1 Score  : {f1:.3f}  (harmonic mean — use this to compare thresholds)")
    print(f"  Accuracy  : {accuracy:.3f}  ({tp + tn}/{len(payloads)} correct)")
    print(f"\n  Latency  P50={p50:.1f}ms  P95={p95:.1f}ms  P99={p99:.1f}ms  (target: <15ms)")

    # ── Wrong predictions ────────────────────────────────────────────────────
    wrong_entries = []
    for atype, d in per_type.items():
        for w in d["wrong"]:
            wrong_entries.append((atype, w["score"], w["note"]))

    if wrong_entries:
        print(f"\n  {'─' * 58}")
        print(f"  Incorrect predictions ({len(wrong_entries)} total):")
        print(f"  {'─' * 58}")
        for atype, score_val, note in sorted(wrong_entries, key=lambda x: x[1], reverse=True):
            label = "MISSED" if atype != "none" else "FALSE_POS"
            print(f"  [{label}] score={score_val:.3f}  type={atype:<15} {note[:45]}")
    else:
        print(f"\n  ✓ Perfect score — no incorrect predictions!")

    # ── Recommendation ───────────────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    if f1 < 0.7:
        print("  RECOMMENDATION: F1 < 0.70 — model needs fine-tuning.")
        print("  Run: python scripts/fine_tune_model.py")
        print("  Then re-run this benchmark to measure improvement.")
    elif f1 < 0.85:
        print("  RECOMMENDATION: F1 0.70–0.85 — acceptable but improvable.")
        print("  Run: python scripts/calibrate_threshold.py")
        print("  to find the optimal threshold for this model.")
    else:
        print("  RECOMMENDATION: F1 > 0.85 — good model performance.")
        print("  Run: python scripts/calibrate_threshold.py")
        print("  to verify this threshold is optimal.")
    print()


if __name__ == "__main__":
    main()
