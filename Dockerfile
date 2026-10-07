FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py checks.py db.py monitor.py ./
COPY selectors.txt sample-clients.csv ./
COPY templates/ templates/
COPY static/ static/

RUN mkdir -p /data && chown -R appuser:appuser /app /data

USER appuser

ENV PORT=8080 DATABASE_PATH=/data/sendergrade.db

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -sf http://127.0.0.1:8080/health || exit 1

CMD ["sh", "-c", "exec gunicorn app:app -b 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 120"]
