FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS rules
RUN pip install --no-cache-dir PyYAML==6.0.3
COPY docker/source-scanner/build.py /build.py
RUN python /build.py

FROM python:3.13-slim@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
LABEL org.opencontainers.image.source="https://github.com/Yeusepe/coolify"
LABEL io.racconify.scanner="opengrep-1.33.1-gitlab-9c375dc49a7c"
COPY --from=rules /out/ /opt/scanner/
COPY docker/source-scanner/scan.py /opt/scanner/scan.py
ENV HOME=/tmp OPENGREP_SEND_METRICS=off OPENGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
USER 65534:65534
WORKDIR /src
ENTRYPOINT ["python", "/opt/scanner/scan.py"]
