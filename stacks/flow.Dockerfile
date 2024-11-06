# syntax=docker/dockerfile:1.11@sha256:1f2be5a2aa052cbd9aedf893d17c63277c3d1c51b3fb0f3b029c6b34f658d057

FROM golang:1.23-alpine@sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679 AS builder
RUN apk add --no-cache gcc geos-dev musl-dev
WORKDIR /root/flow

# first copy only go.mod and go.sum to cache dependencies
COPY flow/go.mod flow/go.sum ./

# download all the dependencies
RUN go mod download

# Copy all the code
COPY flow .

# build the binary from flow folder
WORKDIR /root/flow
ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o /root/peer-flow

FROM alpine:3.20@sha256:beefdbd8a1da6d2915566fde36db9db0b524eb737fc57cd1367effd16dc0d06d AS flow-base
RUN apk add --no-cache ca-certificates geos && \
  adduser -s /bin/sh -D peerdb
USER peerdb
WORKDIR /home/peerdb
COPY --from=builder --chown=peerdb /root/peer-flow .

FROM flow-base AS flow-api

ARG PEERDB_VERSION_SHA_SHORT
ENV PEERDB_VERSION_SHA_SHORT=${PEERDB_VERSION_SHA_SHORT}

EXPOSE 8112 8113
ENTRYPOINT [\
  "./peer-flow",\
  "api",\
  "--port",\
  "8112",\
  "--gateway-port",\
  "8113"\
  ]

FROM flow-base AS flow-worker

# Sane defaults for OpenTelemetry
ENV OTEL_METRIC_EXPORT_INTERVAL=10000
ENV OTEL_EXPORTER_OTLP_COMPRESSION=gzip

ENTRYPOINT [\
  "./peer-flow",\
  "worker"\
  ]

FROM flow-base AS flow-snapshot-worker
ENTRYPOINT [\
  "./peer-flow",\
  "snapshot-worker"\
  ]
