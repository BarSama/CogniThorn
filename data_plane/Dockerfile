# ─── Stage 1: Model downloader ───────────────────────────────────────────────
FROM python:3.11-slim AS model-downloader

WORKDIR /model-workspace
RUN pip install --no-cache-dir huggingface_hub optimum[onnxruntime] transformers

COPY scripts/download_model.py /model-workspace/scripts/
COPY shared/ /model-workspace/shared/
COPY models/ /model-workspace/models/

RUN python scripts/download_model.py

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Install shared package first (layer cache)
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared/

# Install data_plane dependencies
COPY data_plane/requirements.txt /app/data_plane/requirements.txt
RUN pip install --no-cache-dir -r /app/data_plane/requirements.txt

# Copy application code
COPY data_plane/ /app/data_plane/
COPY scripts/ /app/scripts/

# Copy ONNX model from downloader stage
COPY --from=model-downloader /model-workspace/models/ /app/models/

WORKDIR /app
ENV PYTHONPATH=/app
ENV ONNX_MODEL_PATH=/app/models/model.onnx

EXPOSE 9000
CMD ["uvicorn", "data_plane.main:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1"]
