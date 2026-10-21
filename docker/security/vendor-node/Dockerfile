ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG SECURITY_PROFILE
USER 0
ENV NODE_OPTIONS=--use-openssl-ca
COPY docker/security/vendor-node/patch.cjs /tmp/racconify-patch.cjs
RUN if [ "$SECURITY_PROFILE" = meta ]; then \
      npm install --prefix /tmp/runtime-security --install-strategy=nested --ignore-scripts --omit=dev --no-audit --no-fund piscina@5.3.2 proxy-addr@2.0.8 tinypool@2.1.2; \
    elif [ "$SECURITY_PROFILE" = storage ]; then \
      npm install --prefix /tmp/runtime-security --install-strategy=nested --ignore-scripts --omit=dev --no-audit --no-fund fastify@5.12.7 undici@7.29.1; \
    else exit 1; fi && \
    node /tmp/racconify-patch.cjs "$SECURITY_PROFILE" && \
    rm -rf /tmp/runtime-security /tmp/racconify-patch.cjs /root/.npm /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
