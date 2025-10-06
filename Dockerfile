# Builder阶段
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY . .

ENV CGO_ENABLED=0

# 下载并整理依赖
RUN go mod tidy

# 构建二进制
RUN go build -v -o XrayR -trimpath -ldflags "-s -w -buildid="

# Release阶段
FROM alpine:latest

# 安装基础工具
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 创建配置目录
RUN mkdir -p /etc/XrayR/

# 拷贝构建好的二进制
COPY --from=builder /app/XrayR /usr/local/bin/

# 默认启动命令
ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml" ]
