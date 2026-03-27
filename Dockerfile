ARG UV_VERSION=0.9.15
ARG PYTHON_VERSION=3.12

FROM ghcr.io/astral-sh/uv:${UV_VERSION}-python${PYTHON_VERSION}-bookworm-slim AS builder

ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never

WORKDIR /zae

COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY . /zae
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

RUN groupadd -r appgroup && \
    useradd -r -g appgroup -m -d /home/zae zae

ENV PATH="/zae/.venv/bin:$PATH" PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never

WORKDIR /zae

COPY --from=builder --chown=zae:appgroup /zae /zae

USER zae

EXPOSE 8000
CMD ["granian_run.sh"]
