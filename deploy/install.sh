#!/bin/bash

# Router OS 安装脚本
# 用于将Router OS部署到Linux系统并设置为开机自启动

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
INSTALL_DIR="/opt/router-os"
SERVICE_NAME="router-os"
CONFIG_FILE="config.json"
BINARY_NAME="router-os"
LOG_DIR="/var/log/router-os"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本需要root权限运行"
        print_info "请使用: sudo $0"
        exit 1
    fi
}

# 检查系统要求
check_requirements() {
    print_info "检查系统要求..."
    
    # 检查systemd
    if ! command -v systemctl &> /dev/null; then
        print_error "系统不支持systemd，无法安装服务"
        exit 1
    fi
    
    # 检查必要的命令
    local required_commands=("ip" "iptables" "sysctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_warning "命令 '$cmd' 未找到，可能影响路由功能"
        fi
    done
    
    print_success "系统要求检查完成"
}

# 停止现有服务
stop_existing_service() {
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_info "停止现有的 $SERVICE_NAME 服务..."
        systemctl stop "$SERVICE_NAME"
        print_success "服务已停止"
    fi
}

# 创建安装目录
create_directories() {
    print_info "创建安装目录..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    
    # 设置权限
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$LOG_DIR"
    
    print_success "目录创建完成"
}

# 安装二进制文件
install_binary() {
    print_info "安装Router OS二进制文件..."
    
    if [[ ! -f "$BINARY_NAME" ]]; then
        print_error "未找到二进制文件 '$BINARY_NAME'"
        print_info "请先运行 'make build' 构建项目"
        exit 1
    fi
    
    # 复制二进制文件
    cp "$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    
    print_success "二进制文件安装完成"
}

# 安装配置文件
install_config() {
    print_info "安装配置文件..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "未找到配置文件 '$CONFIG_FILE'"
        exit 1
    fi
    
    # 如果目标配置文件已存在，备份它
    if [[ -f "$INSTALL_DIR/$CONFIG_FILE" ]]; then
        cp "$INSTALL_DIR/$CONFIG_FILE" "$INSTALL_DIR/$CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
        print_info "已备份现有配置文件"
    fi
    
    # 复制配置文件
    cp "$CONFIG_FILE" "$INSTALL_DIR/"
    chmod 644 "$INSTALL_DIR/$CONFIG_FILE"
    
    print_success "配置文件安装完成"
}

# 安装systemd服务
install_service() {
    print_info "安装systemd服务..."
    
    if [[ ! -f "deploy/$SERVICE_NAME.service" ]]; then
        print_error "未找到服务文件 'deploy/$SERVICE_NAME.service'"
        exit 1
    fi
    
    # 复制服务文件
    cp "deploy/$SERVICE_NAME.service" "/etc/systemd/system/"
    
    # 重新加载systemd
    systemctl daemon-reload
    
    print_success "systemd服务安装完成"
}

# 启用并启动服务
enable_service() {
    print_info "启用并启动Router OS服务..."
    
    # 启用服务（开机自启动）
    systemctl enable "$SERVICE_NAME"
    
    # 启动服务
    systemctl start "$SERVICE_NAME"
    
    # 检查服务状态
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Router OS服务启动成功"
    else
        print_error "Router OS服务启动失败"
        print_info "查看日志: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
}

# 配置系统参数
configure_system() {
    print_info "配置系统参数..."
    
    # 启用IP转发
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-router-os.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-router-os.conf
    
    # 应用配置
    sysctl -p /etc/sysctl.d/99-router-os.conf
    
    print_success "系统参数配置完成"
}

# 显示安装后信息
show_post_install_info() {
    print_success "Router OS 安装完成！"
    echo
    print_info "安装信息:"
    echo "  - 安装目录: $INSTALL_DIR"
    echo "  - 配置文件: $INSTALL_DIR/$CONFIG_FILE"
    echo "  - 日志目录: $LOG_DIR"
    echo "  - 服务名称: $SERVICE_NAME"
    echo
    print_info "常用命令:"
    echo "  - 查看服务状态: systemctl status $SERVICE_NAME"
    echo "  - 启动服务: systemctl start $SERVICE_NAME"
    echo "  - 停止服务: systemctl stop $SERVICE_NAME"
    echo "  - 重启服务: systemctl restart $SERVICE_NAME"
    echo "  - 查看日志: journalctl -u $SERVICE_NAME -f"
    echo "  - 编辑配置: nano $INSTALL_DIR/$CONFIG_FILE"
    echo
    print_info "配置修改后请重启服务: systemctl restart $SERVICE_NAME"
}

# 卸载函数
uninstall() {
    print_info "开始卸载Router OS..."
    
    # 停止并禁用服务
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        print_info "已禁用服务"
    fi
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        print_info "已停止服务"
    fi
    
    # 删除服务文件
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        print_info "已删除服务文件"
    fi
    
    # 删除安装目录
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        print_info "已删除安装目录"
    fi
    
    # 删除系统配置
    if [[ -f "/etc/sysctl.d/99-router-os.conf" ]]; then
        rm -f "/etc/sysctl.d/99-router-os.conf"
        print_info "已删除系统配置"
    fi
    
    print_success "Router OS 卸载完成"
}

# 主函数
main() {
    echo "========================================"
    echo "       Router OS 安装脚本"
    echo "========================================"
    echo
    
    case "${1:-install}" in
        "install")
            check_root
            check_requirements
            stop_existing_service
            create_directories
            install_binary
            install_config
            install_service
            configure_system
            enable_service
            show_post_install_info
            ;;
        "uninstall")
            check_root
            uninstall
            ;;
        "help"|"-h"|"--help")
            echo "用法: $0 [install|uninstall|help]"
            echo
            echo "命令:"
            echo "  install    安装Router OS (默认)"
            echo "  uninstall  卸载Router OS"
            echo "  help       显示此帮助信息"
            ;;
        *)
            print_error "未知命令: $1"
            echo "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"