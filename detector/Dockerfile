# syntax=docker/dockerfile:1
FROM python:3.11-alpine AS builder
WORKDIR /build
RUN apk update && apk upgrade --no-cache
RUN pip install --no-cache-dir "pip==24.3.1" "setuptools==75.8.0" "wheel==0.45.1"
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-alpine AS runtime
WORKDIR /app
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache iptables && \
    addgroup -S appgroup && adduser -S -G appgroup -H appuser
RUN pip install --no-cache-dir "pip==24.3.1" "setuptools==75.8.0" "wheel==0.45.1"
COPY --from=builder /install /usr/local
COPY *.py config.yaml ./

EXPOSE 8080
CMD ["python", "main.py", "--config", "/app/config.yaml"]
