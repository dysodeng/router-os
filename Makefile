# Router OS Makefile

.PHONY: build test clean run demo help install uninstall deploy setup-network package

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

# 构建发布版本
build-release:
	@echo "构建发布版本..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o router-os-linux-amd64 main.go
	@echo "发布版本构建完成: router-os-linux-amd64"

# 打包部署文件
package: build-release
	@echo "打包部署文件..."
	mkdir -p dist
	cp router-os-linux-amd64 dist/
	cp -r deploy dist/
	cp config.json dist/
	cp README.md dist/ 2>/dev/null || true
	cd dist && tar -czf router-os-deploy.tar.gz router-os-linux-amd64 deploy config.json README.md 2>/dev/null || tar -czf router-os-deploy.tar.gz router-os-linux-amd64 deploy config.json
	@echo "部署包已创建: dist/router-os-deploy.tar.gz"

# 安装到系统（需要root权限）
install: build-release
	@echo "安装 Router OS 到系统..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "错误: 需要root权限安装"; \
		echo "请使用: sudo make install"; \
		exit 1; \
	fi
	./deploy/install.sh install

# 从系统卸载（需要root权限）
uninstall:
	@echo "从系统卸载 Router OS..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "错误: 需要root权限卸载"; \
		echo "请使用: sudo make uninstall"; \
		exit 1; \
	fi
	./deploy/install.sh uninstall

# 配置网络环境（需要root权限）
setup-network:
	@echo "配置网络环境..."
	@if [ "$$(id -u)" != "0" ]; then \
		echo "错误: 需要root权限配置网络"; \
		echo "请使用: sudo make setup-network"; \
		exit 1; \
	fi
	./deploy/setup-network.sh setup

# 完整部署（构建、安装、配置网络）
deploy: package install setup-network
	@echo "Router OS 部署完成！"
	@echo "使用以下命令管理服务:"
	@echo "  systemctl start router-os    - 启动服务"
	@echo "  systemctl stop router-os     - 停止服务"
	@echo "  systemctl status router-os   - 查看状态"
	@echo "  systemctl enable router-os   - 开机自启"

# 显示帮助信息
help:
	@echo "Router OS 构建工具"
	@echo ""
	@echo "构建命令:"
	@echo "  build         - 构建可执行文件"
	@echo "  build-release - 构建Linux发布版本"
	@echo "  package       - 打包部署文件"
	@echo ""
	@echo "开发命令:"
	@echo "  test          - 运行单元测试"
	@echo "  demo          - 运行基本功能演示"
	@echo "  run           - 构建并运行路由器"
	@echo "  clean         - 清理构建文件"
	@echo "  fmt           - 格式化代码"
	@echo "  vet           - 检查代码"
	@echo "  deps          - 下载依赖"
	@echo "  check         - 完整检查（格式化、检查、测试）"
	@echo ""
	@echo "部署命令（需要root权限）:"
	@echo "  install       - 安装到系统"
	@echo "  uninstall     - 从系统卸载"
	@echo "  setup-network - 配置网络环境"
	@echo "  deploy        - 完整部署（构建+安装+配置）"
	@echo ""
	@echo "其他命令:"
	@echo "  help          - 显示此帮助信息"