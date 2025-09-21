# 多阶段构建
FROM registry.huaxisy.com/library/golang:1.24.2 AS builder

# 设置工作目录
WORKDIR /app

# 安装必要的包，包括CGO和SQLite支持
RUN apt-get update && apt-get install -y git gcc libc6-dev libsqlite3-dev && rm -rf /var/lib/apt/lists/*

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用，启用CGO以支持SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -a -o router-os ./cmd/router

# 运行阶段
FROM registry.huaxisy.com/library/alpine:3.21

# 安装必要的包
RUN apk --no-cache add ca-certificates iptables iproute2

# 创建非root用户
RUN addgroup -g 1001 router && \
    adduser -D -s /bin/sh -u 1001 -G router router

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/router-os .

# 复制配置文件
COPY config.json .

# 创建必要的目录
RUN mkdir -p /var/log/router-os && \
    chown -R router:router /app /var/log/router-os

# 暴露端口
EXPOSE 8080

# 设置用户
USER router

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/status || exit 1

# 启动命令
CMD ["./router-os"]