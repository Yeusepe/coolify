# Versions
# https://hub.docker.com/r/serversideup/php/tags?name=8.4-fpm-nginx-alpine
# Pinned: v5 moved user bundles to /etc/s6-overlay/user-bundles.d and breaks startup (#12141)
ARG PHP_BASE_IMAGE=ghcr.io/yeusepe/coolify:php-security-20261024@sha256:664b848340ad939fcceb54537db6653a4e2a4772b5eff0d516ee490b83fb7830
ARG TERMINAL_NODE_IMAGE=node:24.22.1-alpine3.23@sha256:0468540aa58203ff9e40c2aab3907c52644ab818af6176b1c70a026137dc92a2
# https://github.com/cloudflare/cloudflared/releases
ARG CLOUDFLARED_VERSION=2026.10.2
# https://www.postgresql.org/support/versioning/
# Note: We are using version 18 of the postgres client (while still using postgres 15 for the postgres server) as version 15 has been removed from Alpine 3.23+ https://pkgs.alpinelinux.org/packages?name=postgresql*-client&branch=v3.23&repo=&arch=x86_64&origin=&flagged=&maintainer=
ARG POSTGRES_VERSION=18
# https://nginx.org/en/linux_packages.html
ARG NGINX_VERSION=1.31.8-r1
# uv 0.3.0 source, pinned to avoid intermittent PECL download failures.
ARG PHP_UV_SOURCE=amphp/ext-uv@1d18f5d1d12e77c24b6b0b9d69194b1051efae66

# Add user/group
ARG USER_ID=9999
ARG GROUP_ID=9999

# =================================================================
# Stage 1: Composer dependencies
# =================================================================
FROM ${PHP_BASE_IMAGE} AS base

USER root

# Install patched Nginx from the official nginx.org Alpine repository
ARG NGINX_VERSION
RUN set -eux; \
    apk add --no-cache ca-certificates curl; \
    NGINX_ALPINE_VERSION="$(egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release)"; \
    NGINX_REPOSITORY="https://nginx.org/packages/mainline/alpine/v${NGINX_ALPINE_VERSION}/main"; \
    sed -i 's|http://nginx.org/packages|https://nginx.org/packages|g' /etc/apk/repositories; \
    grep -qxF "@nginx ${NGINX_REPOSITORY}" /etc/apk/repositories || echo "@nginx ${NGINX_REPOSITORY}" >> /etc/apk/repositories; \
    curl -fsSL https://nginx.org/keys/nginx_signing.rsa.pub -o /etc/apk/keys/nginx_signing.rsa.pub; \
    apk add --no-cache --upgrade "nginx@nginx=${NGINX_VERSION}"; \
    rm -f /etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf; \
    nginx -v

ARG USER_ID
ARG GROUP_ID

RUN docker-php-serversideup-set-id www-data $USER_ID:$GROUP_ID && \
    docker-php-serversideup-set-file-permissions --owner $USER_ID:$GROUP_ID --service nginx

COPY docker/security/bun/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/security/empty-ca-directory

WORKDIR /var/www/html
COPY --chown=www-data:www-data composer.json composer.lock ./
RUN --mount=type=cache,target=/tmp/cache \
    COMPOSER_CACHE_DIR=/tmp/cache composer install --no-dev --no-interaction --no-plugins --no-scripts --prefer-dist

USER www-data

# =================================================================
# Stage 2: Frontend assets compilation
# =================================================================
FROM ${TERMINAL_NODE_IMAGE} AS static-assets

WORKDIR /app
COPY package*.json vite.config.js postcss.config.cjs ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci
COPY . .
RUN npm run build

# =================================================================
# Stage 3: Get MinIO client
# =================================================================
FROM quay.io/minio/aistor/mc:RELEASE.2026-09-06T02-44-40Z AS minio-client

# =================================================================
# Stage 4: Terminal dependencies (match the production Node.js ABI and libc)
# =================================================================
FROM ${TERMINAL_NODE_IMAGE} AS terminal-node

FROM ${PHP_BASE_IMAGE} AS terminal-dependencies

USER root

COPY --from=terminal-node /usr/local/bin/node /usr/local/bin/node
RUN apk upgrade && \
    apk add --no-cache nodejs npm make g++ python3
COPY docker/security/bun/brotli-regression.cjs /tmp/brotli-regression.cjs
RUN node /tmp/brotli-regression.cjs && rm /tmp/brotli-regression.cjs
COPY docker/coolify-terminal/package*.json /terminal/
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefix /terminal && \
    npm rebuild node-pty --prefix /terminal --update-binary && \
    rm -rf /terminal/node_modules/node-pty/prebuilds/darwin-* \
        /terminal/node_modules/node-pty/prebuilds/win32-*
COPY docker/coolify-terminal/terminal-server.js /terminal/terminal-server.js
COPY docker/coolify-terminal/terminal-utils.js /terminal/terminal-utils.js

# =================================================================
# Final Stage: Production image
# =================================================================
FROM ${PHP_BASE_IMAGE}

ARG USER_ID
ARG GROUP_ID
ARG TARGETPLATFORM
ARG POSTGRES_VERSION
ARG CLOUDFLARED_VERSION
ARG NGINX_VERSION
ARG PHP_UV_SOURCE
ARG COOLIFY_VERSION
ARG CI=true

ENV COOLIFY_VERSION=${COOLIFY_VERSION}

WORKDIR /var/www/html

USER root

# Install patched Nginx from the official nginx.org Alpine repository
RUN set -eux; \
    apk add --no-cache ca-certificates curl; \
    NGINX_ALPINE_VERSION="$(egrep -o '^[0-9]+\.[0-9]+' /etc/alpine-release)"; \
    NGINX_REPOSITORY="https://nginx.org/packages/mainline/alpine/v${NGINX_ALPINE_VERSION}/main"; \
    sed -i 's|http://nginx.org/packages|https://nginx.org/packages|g' /etc/apk/repositories; \
    grep -qxF "@nginx ${NGINX_REPOSITORY}" /etc/apk/repositories || echo "@nginx ${NGINX_REPOSITORY}" >> /etc/apk/repositories; \
    curl -fsSL https://nginx.org/keys/nginx_signing.rsa.pub -o /etc/apk/keys/nginx_signing.rsa.pub; \
    apk add --no-cache --upgrade "nginx@nginx=${NGINX_VERSION}"; \
    rm -f /etc/nginx/nginx.conf /etc/nginx/conf.d/default.conf; \
    nginx -v

RUN docker-php-serversideup-set-id www-data $USER_ID:$GROUP_ID && \
    docker-php-serversideup-set-file-permissions --owner $USER_ID:$GROUP_ID --service nginx

# Install PostgreSQL repository and keys
RUN apk add --no-cache gnupg && \
    mkdir -p /usr/share/keyrings && \
    curl -fSsL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /usr/share/keyrings/postgresql.gpg

# Install system dependencies
RUN --mount=type=cache,target=/var/cache/apk \
    apk upgrade && \
    apk add --no-cache \
    postgresql${POSTGRES_VERSION}-client \
    libstdc++ \
    openssh-client \
    git \
    git-lfs \
    jq \
    lsof \
    procps \
    vim

COPY --from=terminal-node /usr/local/bin/node /usr/local/bin/node
COPY docker/security/bun/brotli-regression.cjs /tmp/brotli-regression.cjs
RUN node /tmp/brotli-regression.cjs && rm /tmp/brotli-regression.cjs
COPY docker/security/bun/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN mkdir -p /run/security/empty-ca-directory
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/security/empty-ca-directory NODE_OPTIONS=--use-openssl-ca

# Install PHP extensions
# uv: Reverb uses an ext-uv event loop instead of stream_select(), which fails at 1024 open files (FD_SETSIZE)
RUN install-php-extensions "${PHP_UV_SOURCE}"

# Configure shell aliases
RUN echo "alias ll='ls -al'" >> /etc/profile && \
    echo "alias a='php artisan'" >> /etc/profile && \
    echo "alias logs='tail -f storage/logs/laravel.log'" >> /etc/profile

# Install Cloudflared based on architecture
RUN mkdir -p /usr/local/bin && \
    if [ "${TARGETPLATFORM}" = "linux/amd64" ]; then \
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64" -o /usr/local/bin/cloudflared; \
    elif [ "${TARGETPLATFORM}" = "linux/arm64" ]; then \
    curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-arm64" -o /usr/local/bin/cloudflared; \
    fi && \
    chmod +x /usr/local/bin/cloudflared

# Configure PHP
COPY docker/production/etc/php/conf.d/zzz-custom-php.ini /usr/local/etc/php/conf.d/zzz-custom-php.ini
ENV PHP_OPCACHE_ENABLE=1

# Configure entrypoint
COPY --chmod=755 docker/production/entrypoint.d/ /etc/entrypoint.d

# Copy application files from previous stages
COPY --from=base --chown=www-data:www-data /var/www/html/vendor ./vendor
COPY --from=static-assets --chown=www-data:www-data /app/public/build ./public/build

# Copy application source code
COPY --chown=www-data:www-data composer.json composer.lock ./
COPY --chown=www-data:www-data app ./app
COPY --chown=www-data:www-data bootstrap ./bootstrap
COPY --chown=www-data:www-data config ./config
COPY --chown=www-data:www-data database ./database
COPY --chown=www-data:www-data lang ./lang
COPY --chown=www-data:www-data public ./public
COPY --chown=www-data:www-data routes ./routes
COPY --chown=www-data:www-data storage ./storage
COPY --chown=www-data:www-data templates ./templates
COPY --chown=www-data:www-data resources/views ./resources/views
COPY --chown=www-data:www-data artisan artisan
COPY --chown=www-data:www-data openapi.yaml ./openapi.yaml
COPY --chown=www-data:www-data changelogs/ ./changelogs/
# Version data for Traefik, Sentinel, and helper checks until CheckForUpdatesJob refreshes it
COPY --chown=www-data:www-data versions.json ./versions.json

RUN composer dump-autoload

# Install terminal WebSocket server dependencies
COPY --from=terminal-dependencies --chown=www-data:www-data /terminal /terminal

# Configure Nginx and S6 overlay
COPY docker/production/etc/nginx/conf.d/custom.conf /etc/nginx/conf.d/custom.conf
COPY docker/production/etc/nginx/site-opts.d/http.conf /etc/nginx/site-opts.d/http.conf
COPY --chmod=755 docker/production/etc/s6-overlay/ /etc/s6-overlay/

RUN mkdir -p /etc/nginx/conf.d && \
    chown -R www-data:www-data /etc/nginx && \
    chmod -R 755 /etc/nginx

# Install MinIO client
COPY --from=minio-client /usr/bin/mc /usr/bin/mc
RUN chmod +x /usr/bin/mc

# Switch to non-root user
USER www-data
