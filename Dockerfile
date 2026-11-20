# AgentVerify pilot image. No keys or secrets are baked in: every secret is read
# from environment variables at start-up (see DEPLOY.md).
# Python 3.14 matches the only version the project has been tested on.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app ./app
COPY agentverify_client ./agentverify_client
COPY migrations ./migrations
COPY LICENSE README.md ./

# Non-root user. /app stays root-owned (read-only for the service); the usage
# telemetry file goes to /tmp (AGENTVERIFY_USAGE_DB), which is writable.
RUN useradd --system --no-create-home --uid 10001 agentverify
USER agentverify

# Render injects PORT (default 10000). Guarded launcher binds 0.0.0.0:$PORT, one worker.
EXPOSE 10000
CMD ["sh", "-c", "exec python -B -m app.secure_launch --host 0.0.0.0 --port ${PORT:-10000}"]
