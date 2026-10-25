FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
USER root
RUN npm install --global --omit=dev mongosh@2.13.0
COPY docker/security/vendor-node/dependencies.cjs docker/security/vendor-node/profiles.json docker/security/vendor-node/zod-compat.cjs docker/security/vendor-node/legacy-app-patches.cjs /tmp/reviewed-patches/
RUN mkdir -p /opt/security-npm && cp -a /usr/local/lib/node_modules/npm/. /opt/security-npm/ && node /tmp/reviewed-patches/dependencies.cjs mongosh && node /tmp/reviewed-patches/legacy-app-patches.cjs mongosh && mongosh --nodb --quiet --eval 'if (process.version !== "v24.22.1") throw new Error("Unexpected Node runtime"); print("mongosh security runtime ready")' && rm -rf /opt/security-npm /tmp/reviewed-patches
