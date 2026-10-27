# Imou -> RTSP bridge for Synology Container Manager (amd64 / arm64).
ARG MEDIAMTX_VERSION=1.21.3
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM bluenviron/mediamtx:${MEDIAMTX_VERSION} AS mediamtx

FROM ${PYTHON_IMAGE}

LABEL org.opencontainers.image.title="imou-rtsp" \
      org.opencontainers.image.description="Expose Imou Life cameras as RTSP streams (MediaMTX)" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    DATA_DIR=/data \
    MEDIAMTX_BIN=/usr/local/bin/mediamtx

RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/imou-rtsp

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY --from=mediamtx /mediamtx /usr/local/bin/mediamtx
COPY app ./app
COPY LICENSE THIRD_PARTY_NOTICES.md ./

RUN mkdir -p /data && python -m compileall -q app

EXPOSE 8090/tcp 8554/tcp 8000/udp 8001/udp

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["python", "-m", "app.healthcheck"]

CMD ["python", "-m", "app"]
