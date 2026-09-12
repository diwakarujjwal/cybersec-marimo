# Hardened sandboxed Marimo container for Linux Incident Response
FROM python:3.11-slim

RUN groupadd -g 1000 marimo && \
    useradd -u 1000 -g marimo -m -s /bin/bash marimo

WORKDIR /workspace
RUN pip install --no-cache-dir marimo

COPY marimo/ /workspace/marimo/
COPY data/ /workspace/data/
COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R marimo:marimo /workspace

USER 1000:1000
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]

