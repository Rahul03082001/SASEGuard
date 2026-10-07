# One image, four services. Which one starts is decided by the command in
# docker-compose.yml, so there is exactly one dependency set and one build to
# keep consistent.
FROM python:3.12-slim-bookworm

# Never write .pyc, never buffer stdout (so `docker compose logs` is live).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Dependencies first: this layer is cached until requirements.txt changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Only what the services need at runtime. Tests, docs and .git are excluded
# by .dockerignore, as are secrets/, data/ and .env -- the image must never
# contain generated credentials.
COPY apps/ ./apps/
COPY config/ ./config/
COPY web/ ./web/
COPY scripts/ ./scripts/

# Run as a non-root user. If the gateway is ever compromised, the attacker
# starts without the ability to write to /app or install packages.
RUN useradd --create-home --uid 10001 saseguard \
 && mkdir -p /app/data /app/secrets \
 && chown -R saseguard:saseguard /app
USER saseguard

# Documentation only; the host port mapping is in docker-compose.yml and is
# bound to 127.0.0.1 there.
EXPOSE 8080

# Overridden per service in Compose.
CMD ["python", "-m", "uvicorn", "apps.gateway:app", "--host", "0.0.0.0", "--port", "8080"]
