FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SHADOW_HUNTER_HOST=0.0.0.0 \
    SHADOW_HUNTER_PORT=8000 \
    SHADOW_HUNTER_DB_PATH=/data/shadow_hunter.sqlite3

RUN groupadd --system --gid 10001 shadowhunter \
    && useradd --system --uid 10001 --gid shadowhunter --home-dir /app shadowhunter

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[server]" \
    && mkdir -p /data /tmp \
    && chown -R shadowhunter:shadowhunter /app /data /tmp

USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["shadow-hunter-api"]
