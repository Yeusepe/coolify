FROM chrislusf/seaweedfs@sha256:c2658820e763294a9e9de7b36c81e59b879e3459148351aee4e31a126ca64860
USER root
RUN apk upgrade --no-cache
ADD --checksum=sha256:c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee https://github.com/seaweedfs/seaweedfs/releases/download/4.51/linux_amd64.tar.gz /tmp/seaweed.tar.gz
RUN tar -xzf /tmp/seaweed.tar.gz -C /usr/bin weed && chmod 755 /usr/bin/weed && rm /tmp/seaweed.tar.gz && weed version | grep -q '4.51'
COPY docker/security/bun/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/empty-ca-directory
ENTRYPOINT ["/usr/bin/weed"]
CMD ["mini", "-dir=/data"]
