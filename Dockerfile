FROM caddy:2.11.4-alpine AS caddy

FROM python:3.13-slim
ARG TARGETARCH
ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    PANEL_PORT=8000 \
    XRAY_PORT=10000 \
    DATA_DIR=/data

WORKDIR /app

COPY --from=caddy /usr/bin/caddy /usr/bin/caddy

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && set -eux; \
       case "${TARGETARCH}" in \
         amd64) XRAY_ASSET="Xray-linux-64.zip" ;; \
         arm64) XRAY_ASSET="Xray-linux-arm64-v8a.zip" ;; \
         arm) XRAY_ASSET="Xray-linux-arm32-v7a.zip" ;; \
         *) echo "Unsupported TARGETARCH=${TARGETARCH}"; exit 1 ;; \
       esac; \
       curl -fsSL --retry 3 -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/v26.9.8/${XRAY_ASSET}"; \
       unzip -j /tmp/xray.zip xray -d /usr/local/bin; \
       chmod +x /usr/local/bin/xray; \
       rm -f /tmp/xray.zip

COPY main.py requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY Caddyfile /etc/caddy/Caddyfile
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 8080
CMD ["/start.sh"]
