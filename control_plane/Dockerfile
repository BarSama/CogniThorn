FROM python:3.11-slim

WORKDIR /app

# Install shared package
COPY shared/ /app/shared/
RUN pip install --no-cache-dir -e /app/shared/

# Install control_plane dependencies
COPY control_plane/requirements.txt /app/control_plane/requirements.txt
RUN pip install --no-cache-dir -r /app/control_plane/requirements.txt

# Copy application code
COPY control_plane/ /app/control_plane/
COPY scripts/ /app/scripts/

WORKDIR /app
ENV PYTHONPATH=/app
ENV REDIS_URL=redis://redis-master:6379

# supervisord config to run both uvicorn (API) and streamlit (dashboard)
COPY control_plane/supervisord.conf /etc/supervisor/conf.d/cognithhorn.conf

EXPOSE 8090 8501
CMD ["supervisord", "-n", "-c", "/etc/supervisor/conf.d/cognithhorn.conf"]
