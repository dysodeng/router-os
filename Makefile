# Router OS Makefile

.PHONY: build test clean run demo help

# 默认目标
all: build

# 构建可执行文件
build:
	@echo "构建 Router OS..."
	go build -o router-os main.go
	@echo "构建完成: router-os"

# 运行测试
test:
	@echo "运行单元测试..."
	go test ./internal/... -v

# 运行演示程序
demo:
	@echo "运行基本功能演示..."
	go run examples/basic_demo.go

# 运行路由器
run: build
	@echo "启动 Router OS..."
	./router-os

# 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -f router-os
	go clean

# 格式化代码
fmt:
	@echo "格式化代码..."
	go fmt ./...

# 检查代码
vet:
	@echo "检查代码..."
	go vet ./...

# 下载依赖
deps:
	@echo "下载依赖..."
	go mod download
	go mod tidy

# 安装开发工具
install-tools:
	@echo "安装开发工具..."
	go install golang.org/x/tools/cmd/goimports@latest

# 完整检查（格式化、检查、测试）
check: fmt vet test
	@echo "所有检查完成"

# 显示帮助信息
help:
	@echo "Router OS 构建工具"
	@echo ""
	@echo "可用命令:"
	@echo "  build      - 构建可执行文件"
	@echo "  test       - 运行单元测试"
	@echo "  demo       - 运行基本功能演示"
	@echo "  run        - 构建并运行路由器"
	@echo "  clean      - 清理构建文件"
	@echo "  fmt        - 格式化代码"
	@echo "  vet        - 检查代码"
	@echo "  deps       - 下载依赖"
	@echo "  check      - 完整检查（格式化、检查、测试）"
	@echo "  help       - 显示此帮助信息"