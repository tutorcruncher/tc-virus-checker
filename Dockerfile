FROM python:3.12-slim-bookworm

# uv: fast, reproducible installs from uv.lock
COPY --from=ghcr.io/astral-sh/uv:0.8.11 /uv /uvx /usr/local/bin/

# ClamAV: the daemon, the scanner, and the signature updater.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clamav \
        clamav-daemon \
        clamav-freshclam \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY src ./src

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8000

EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.app.main:tc_av_app --host=0.0.0.0 --port=${PORT}"]
