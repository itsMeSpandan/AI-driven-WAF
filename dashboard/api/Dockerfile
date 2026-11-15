FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies
COPY gateway/requirements.txt ./gateway/
RUN pip install --no-cache-dir -r gateway/requirements.txt

# Copy application files
COPY gateway/ ./gateway/
COPY waf_common/ ./waf_common/
COPY ml/ ./ml/
COPY dashboard/api/ ./dashboard/api/
COPY docs/ ./docs/

ENV PYTHONPATH=/app
ENV DB_URL=sqlite:////data/waf.db
ENV DASHBOARD_API_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "dashboard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
