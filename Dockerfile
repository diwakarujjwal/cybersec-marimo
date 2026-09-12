FROM python:3.11-slim

# Install system dependencies & Docker CLI client
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz | tar -xz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/ \
    && rm -rf /tmp/docker \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY cyberlab/ /app/cyberlab/
COPY challenges/ /app/challenges/

EXPOSE 8888

CMD ["uvicorn", "cyberlab.main:app", "--host", "0.0.0.0", "--port", "8888"]

