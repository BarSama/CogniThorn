#!/usr/bin/env python3
"""
INT8 quantization of the CogniThorn ONNX model.

--- What is quantization? ---
The ONNX model stores its weights (learned numbers) as 32-bit floats (4 bytes each).
INT8 quantization replaces those with 8-bit integers (1 byte each).

Why does this work at all? Neural network weights don't need the full precision
of float32. Rounding them to the nearest 1/256th of their range causes <1%
accuracy loss but delivers:
  - Model file: ~250MB → ~65MB (75% smaller)
  - Inference speed: ~40% faster on CPU (int8 math is cheaper than float32)
  - RAM usage: proportionally reduced (helps with the 512MB container limit)

--- Dynamic vs Static quantization ---
Dynamic quantization (what we use): quantize WEIGHTS at conversion time but
compute ACTIVATIONS in float32 at inference time. Simpler — no calibration
dataset needed. Works well for transformer models.

Static quantization: quantize both weights AND activations. Requires running
a representative dataset through the model to measure activation ranges.
Better peak performance but more work. Consider this if dynamic isn't fast enough.

--- How to run ---
  # Model must be downloaded first:
  docker compose run --rm waf-worker python scripts/download_model.py

  # Then quantize:
  docker compose run --rm waf-worker python scripts/quantize_model.py

  # Verify the quantized model still works:
  docker compose exec waf-worker python scripts/benchmark_model.py

  # Restart workers to use quantized model:
  docker compose restart waf-worker
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    model_dir = Path(__file__).parent.parent / "models"
    input_path = model_dir / "model.onnx"
    output_path = model_dir / "model_int8.onnx"

    if not input_path.exists():
        print(f"ERROR: Model not found at {input_path}")
        print("Run first: python scripts/download_model.py")
        sys.exit(1)

    print("CogniThorn ONNX Model Quantizer")
    print(f"Input  : {input_path}  ({input_path.stat().st_size / 1e6:.1f} MB)")
    print(f"Output : {output_path}")
    print()

    try:
        from onnxruntime.quantization import quantize_dynamic, QuantType
    except ImportError:
        print("ERROR: onnxruntime.quantization not available.")
        print("Install with: pip install onnxruntime")
        sys.exit(1)

    print("Running INT8 dynamic quantization...")
    print("(This converts float32 weights to int8 — weights only, activations stay float32)")
    t0 = time.perf_counter()

    quantize_dynamic(
        model_input=str(input_path),
        model_output=str(output_path),
        weight_type=QuantType.QInt8,
        # MatMulConstBOnly=True: only quantize constant (weight) MatMul inputs,
        # not dynamic (activation) inputs. This is safer for transformer models.
        extra_options={"MatMulConstBOnly": True},
    )

    elapsed = time.perf_counter() - t0
    out_size = output_path.stat().st_size / 1e6
    in_size  = input_path.stat().st_size / 1e6
    reduction = (1 - out_size / in_size) * 100

    print(f"\nQuantization complete in {elapsed:.1f}s")
    print(f"  Original  : {in_size:.1f} MB")
    print(f"  Quantized : {out_size:.1f} MB  ({reduction:.0f}% reduction)")
    print()

    # Quick accuracy check: run one inference on both models and compare scores
    print("Verifying accuracy (running one inference on both models)...")
    try:
        import onnxruntime as ort
        import numpy as np
        from shared.config.settings import settings
        from data_plane.detection.tokenizer_utils import build_input_text, encode_request

        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1

        orig_session = ort.InferenceSession(str(input_path), sess_options=opts)
        quant_session = ort.InferenceSession(str(output_path), sess_options=opts)

        # Test on a known SQLi payload
        text = build_input_text("POST", "/login", "", "username=admin' OR '1'='1' --")
        inputs = encode_request(text)

        def softmax(logits):
            e = np.exp(logits - np.max(logits))
            return e / e.sum()

        orig_score  = float(softmax(orig_session.run(None, inputs)[0][0])[1])
        quant_score = float(softmax(quant_session.run(None, inputs)[0][0])[1])
        delta = abs(orig_score - quant_score)

        print(f"  Original score : {orig_score:.4f}")
        print(f"  Quantized score: {quant_score:.4f}")
        print(f"  Delta          : {delta:.4f}  {'✓ acceptable' if delta < 0.05 else '⚠ large — check model'}")
        print()
    except Exception as e:
        print(f"  Could not verify: {e}")
        print()

    # Update symlink or env var suggestion
    print("To use the quantized model, set in your .env:")
    print(f"  ONNX_MODEL_PATH={output_path}")
    print()
    print("Or replace the original (keep a backup):")
    print(f"  cp {input_path} {model_dir}/model_float32_backup.onnx")
    print(f"  cp {output_path} {input_path}")
    print()
    print("Then restart workers: docker compose restart waf-worker")
    print("And benchmark: docker compose exec waf-worker python scripts/benchmark_model.py")


if __name__ == "__main__":
    main()
