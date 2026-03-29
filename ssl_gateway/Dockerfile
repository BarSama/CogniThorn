FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install shared package
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared/

# Install ssl_gateway dependencies
COPY ssl_gateway/requirements.txt /app/ssl_gateway/requirements.txt
RUN pip install --no-cache-dir -r /app/ssl_gateway/requirements.txt

# Copy application code
COPY ssl_gateway/ /app/ssl_gateway/

WORKDIR /app
ENV PYTHONPATH=/app

RUN mkdir -p /certs
VOLUME ["/certs"]

EXPOSE 80 443
CMD ["python", "-m", "ssl_gateway.main"]
