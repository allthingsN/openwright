# OpenWright container image (NFR-PORT-02). Self-hosted; no hosted dependency.
# Build:  docker build -t openwright .
# Run:    docker run --rm openwright demo
FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false

WORKDIR /app

# Install Poetry, then dependencies (cached layer), then the project.
RUN pip install --no-cache-dir "poetry>=2.0"
# README.pypi.md is the readme referenced by pyproject (PyPI long-description),
# so it must be present for `poetry install` to build the project.
COPY pyproject.toml README.md README.pypi.md ./
COPY src ./src
RUN poetry install --only main

# Default signing key is NOT baked in (NFR-SEC-02). Provide one at runtime via a
# mounted file or OPENWRIGHT_SIGNING_KEY env var; the demo generates an ephemeral
# operator-controlled key on disk inside the container.
ENTRYPOINT ["openwright"]
CMD ["demo"]
