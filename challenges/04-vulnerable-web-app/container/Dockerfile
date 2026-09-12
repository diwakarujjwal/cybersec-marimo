# Hardened sandboxed container for Web App Security
FROM python:3.11-slim

RUN groupadd -g 1000 marimo && \
    useradd -u 1000 -g marimo -m -s /bin/bash marimo

WORKDIR /workspace
COPY app/ /workspace/app/
COPY marimo/ /workspace/marimo/
COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R marimo:marimo /workspace

USER 1000:1000
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]

