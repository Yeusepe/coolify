ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG RUNTIME_USER=0
USER 0
RUN if command -v apk >/dev/null; then \
      apk upgrade --no-cache; \
    elif command -v apt-get >/dev/null; then \
      apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*; \
    else \
      echo 'No supported OS package manager; refusing to claim a patched image' >&2; exit 1; \
    fi
COPY docker/security/bun/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/security/empty-ca-directory
USER ${RUNTIME_USER}
