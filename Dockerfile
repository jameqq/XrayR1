# Build stage
FROM golang:1.25.1-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod tidy
RUN go build -v -o XrayR -trimpath -ldflags "-s -w -buildid=" ./cmd/distro/all

# Release stage
FROM alpine:3.18
RUN apk --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir -p /etc/XrayR/
COPY --from=builder /app/XrayR /usr/local/bin/XrayR

ENTRYPOINT ["XrayR", "--config", "/etc/XrayR/config.yml"]
