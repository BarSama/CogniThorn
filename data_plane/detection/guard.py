"""Fast Path: ONNX DistilBERT inference for request threat scoring."""
import asyncio
import logging
import time
from functools import partial

import numpy as np
import onnxruntime as ort

from data_plane.detection.tokenizer_utils import encode_request, build_input_text
from shared.config.settings import settings
from shared.schemas import RequestContext, GuardResult

logger = logging.getLogger(__name__)

# Module-level singleton — loaded once at startup
_session: ort.InferenceSession | None = None


def _load_session() -> ort.InferenceSession:
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 1
    opts.inter_op_num_threads = 1
    opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    session = ort.InferenceSession(settings.onnx_model_path, sess_options=opts)
    return session


def get_session() -> ort.InferenceSession:
    global _session
    if _session is None:
        logger.info("Loading ONNX model from %s", settings.onnx_model_path)
        _session = _load_session()
        _warmup(_session)
    return _session


def _warmup(session: ort.InferenceSession) -> None:
    """Run 3 dummy inferences to JIT-compile the ONNX graph."""
    dummy = encode_request("GET /health HTTP/1.1")
    for _ in range(3):
        session.run(None, dummy)
    logger.info("ONNX model warmed up")


def _run_inference(session: ort.InferenceSession, inputs: dict) -> float:
    """Synchronous inference — run in executor to avoid blocking event loop."""
    start = time.perf_counter()
    outputs = session.run(None, inputs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if elapsed_ms > 20:
        logger.warning("ONNX inference took %.1fms (target <15ms)", elapsed_ms)
    # outputs[0] is logits shape [1, num_classes]; apply softmax to get probabilities
    logits = outputs[0][0]
    exp_logits = np.exp(logits - np.max(logits))
    probs = exp_logits / exp_logits.sum()
    # Assume class 1 = malicious
    malicious_score = float(probs[1]) if len(probs) > 1 else float(probs[0])
    return malicious_score


async def score(ctx: RequestContext, threshold: float | None = None) -> GuardResult:
    """
    Score a request. Returns GuardResult with score and whether it passed.
    Runs inference in a thread pool executor (non-blocking).

    On ANY exception: logs CRITICAL and returns passed=True (Fail-Open).
    """
    if threshold is None:
        threshold = settings.sensitivity_threshold
    try:
        session = get_session()
        text = build_input_text(ctx.method, ctx.path, ctx.query_string, ctx.body)
        inputs = encode_request(text)
        loop = asyncio.get_event_loop()
        malicious_score = await loop.run_in_executor(None, partial(_run_inference, session, inputs))
        return GuardResult(score=malicious_score, passed=malicious_score < threshold)
    except Exception as exc:
        logger.critical("ONNX inference failed — failing open: %s", exc, exc_info=True)
        return GuardResult(score=0.0, passed=True)  # Fail-Open
