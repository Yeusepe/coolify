ARG BASE_IMAGE
ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS patched-node
FROM ${BASE_IMAGE}
USER 0
# The pinned base retains the existing application and dependency security patches.
COPY --from=patched-node /usr/local/bin/node /usr/local/bin/node
COPY docker/security/bun/brotli-regression.cjs /tmp/brotli-regression.cjs
RUN node /tmp/brotli-regression.cjs && rm /tmp/brotli-regression.cjs
ENV NODE_OPTIONS=--use-openssl-ca
