# syntax=docker/dockerfile:1.7

# ---- Builder stage ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Build deps first for layer caching
COPY pyproject.toml README.md /build/
COPY src /build/src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir ".[mcp]"

# ---- Runtime stage ----
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="NeuralStrike"
LABEL org.opencontainers.image.description="Adversarial AI orchestration framework"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/aiagentmackenzie-lang/NeuralStrike"

# Non-root user
RUN useradd --create-home --uid 1000 neuralstrike
WORKDIR /home/neuralstrike

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/src /opt/neuralstrike-src

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NEURALSTRIKE_REDACT_LOGS=true

USER neuralstrike

ENTRYPOINT ["neuralstrike"]
CMD ["--help"]