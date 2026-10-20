FROM golang:1.27.3-bookworm AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN git clone --depth 1 --branch RELEASE.2025-10-15T17-29-55Z https://github.com/minio/minio.git /src/minio && git clone --depth 1 --branch RELEASE.2025-08-13T08-35-41Z https://github.com/minio/mc.git /src/mc
WORKDIR /src/minio
RUN go mod edit -go=1.27.0 -toolchain=go1.27.3 && go get golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.61.0 golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.84.0 github.com/klauspost/compress@v1.20.3 github.com/rabbitmq/amqp091-go@v1.16.0 go.opentelemetry.io/otel/sdk@v1.47.0 && go mod tidy && go build -trimpath -ldflags '-s -w' -o /out/minio . && tar --exclude=.git -czf /out/minio-source.tar.gz .
WORKDIR /src/mc
RUN go mod edit -go=1.27.0 -toolchain=go1.27.3 && go get golang.org/x/crypto@v0.58.0 golang.org/x/net@v0.61.0 golang.org/x/text@v0.43.0 github.com/klauspost/compress@v1.20.3 && go mod tidy && go build -trimpath -ldflags '-s -w' -o /out/mc . && tar --exclude=.git -czf /out/mc-source.tar.gz .
FROM debian:bookworm-slim
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates curl tzdata && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/minio /out/mc /usr/local/bin/
COPY --from=build /out/minio-source.tar.gz /out/mc-source.tar.gz /usr/share/minio/source/
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt SSL_CERT_DIR=/run/empty-ca-directory MINIO_UPDATE=off
EXPOSE 9000 9090
ENTRYPOINT ["minio"]
