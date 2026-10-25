FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d
USER root
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN test "$(bun --revision)" = '1.4.4+38afee6c8'
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/empty-ca-directory
RUN bun -e 'const {X509Certificate}=require("crypto");const roots=require("tls").rootCertificates; if(roots.some(p=>/emSign ECC Root CA - G3|AAA Certificate Services/.test(new X509Certificate(p).subject)))throw new Error("Distrusted CA remains bundled"); if(roots.length<100)throw new Error("CA bundle is incomplete")'

COPY brotli-regression.cjs /tmp/brotli-regression.cjs
RUN bun /tmp/brotli-regression.cjs && rm /tmp/brotli-regression.cjs
