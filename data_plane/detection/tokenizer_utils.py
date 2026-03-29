"""Fast tokenization for ONNX inference using HuggingFace tokenizers (Rust backend)."""
import os
import numpy as np
from tokenizers import Tokenizer
from shared.config.settings import settings

_tokenizer: Tokenizer | None = None

def get_tokenizer() -> Tokenizer:
    global _tokenizer
    if _tokenizer is None:
        tokenizer_path = os.path.join(os.path.dirname(settings.onnx_model_path), "tokenizer.json")
        _tokenizer = Tokenizer.from_file(tokenizer_path)
        _tokenizer.enable_padding(pad_id=0, pad_token="[PAD]", length=512)
        _tokenizer.enable_truncation(max_length=512)
    return _tokenizer

def encode_request(text: str) -> dict[str, np.ndarray]:
    """Encode a request string into ONNX input tensors."""
    tok = get_tokenizer()
    encoding = tok.encode(text)
    return {
        "input_ids": np.array([encoding.ids], dtype=np.int64),
        "attention_mask": np.array([encoding.attention_mask], dtype=np.int64),
    }

def build_input_text(method: str, path: str, query: str, body: str) -> str:
    """Serialize request fields into a single string for the model."""
    body_truncated = body[:512] if body else ""
    return f"METHOD {method} PATH {path} QUERY {query} BODY {body_truncated}"
