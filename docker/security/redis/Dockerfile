FROM redis/redis-stack-server@sha256:798ab84d9f266936b034ab11c4d04a2b8e4b441884c5aa7d17ac951eefdf742a
USER root
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY docker/security/bun/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/security/empty-ca-directory
