FROM oven/bun:1.4.3@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598
USER root
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates unzip && rm -rf /var/lib/apt/lists/*
# shortcut: use the verified upstream CA fix until it ships in a stable Bun release
ADD --checksum=sha256:3e6d716533e5a44bc797ced53fcf2cde23fa2081a225bf8e2d0598fb98b742a7 https://github.com/oven-sh/bun/releases/download/canary/bun-linux-x64.zip /tmp/bun.zip
RUN unzip -p /tmp/bun.zip bun-linux-x64/bun > /usr/local/bin/bun && chmod 755 /usr/local/bin/bun && rm /tmp/bun.zip && test "$(bun --revision)" = '1.4.4-canary.1+9b4284f78'
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/empty-ca-directory
RUN bun -e 'const {X509Certificate}=require("crypto");const roots=require("tls").rootCertificates; if(roots.some(p=>/emSign|eMudhra|AAA Certificate Services/.test(new X509Certificate(p).subject)))throw new Error("Distrusted CA remains bundled"); if(roots.length<100)throw new Error("CA bundle is incomplete")'
