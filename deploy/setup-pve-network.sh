#!/bin/bash

# PVE Router OS 网络配置脚本
# 专门用于配置双网卡NAT转发环境
# ens18: 外网接口 (WAN)
# ens20: 内网接口 (LAN)

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置变量
WAN_INTERFACE="ens18"
LAN_INTERFACE="ens20"
LAN_NETWORK="192.168.2.0/24"
LAN_IP="192.168.2.1"
DHCP_START="192.168.2.100"
DHCP_END="192.168.2.200"

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

# 检查网络接口是否存在
check_interfaces() {
    print_info "检查网络接口..."
    
    if ! ip link show "$WAN_INTERFACE" &> /dev/null; then
        print_error "外网接口 $WAN_INTERFACE 不存在"
        print_info "可用接口:"
        ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
        exit 1
    fi
    
    if ! ip link show "$LAN_INTERFACE" &> /dev/null; then
        print_error "内网接口 $LAN_INTERFACE 不存在"
        print_info "可用接口:"
        ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
        exit 1
    fi
    
    print_success "网络接口检查通过"
}

# 配置网络接口
configure_interfaces() {
    print_info "配置网络接口..."
    
    # 启用接口
    ip link set "$WAN_INTERFACE" up
    ip link set "$LAN_INTERFACE" up
    
    # 配置LAN接口IP
    # 先清除现有IP
    ip addr flush dev "$LAN_INTERFACE"
    # 设置新IP
    ip addr add "$LAN_IP/24" dev "$LAN_INTERFACE"
    
    print_success "网络接口配置完成"
    print_info "LAN接口 $LAN_INTERFACE: $LAN_IP/24"
}

# 启用IP转发
enable_ip_forwarding() {
    print_info "启用IP转发..."
    
    # 临时启用
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # 永久启用
    cat > /etc/sysctl.d/99-router-os-forwarding.conf << EOF
# Router OS IP转发配置
net.ipv4.ip_forward = 1

# 网络性能优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# 安全设置
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
    
    # 应用配置
    sysctl -p /etc/sysctl.d/99-router-os-forwarding.conf
    
    print_success "IP转发已启用"
}

# 配置NAT规则
configure_nat() {
    print_info "配置NAT转发规则..."
    
    # 清除现有规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # 设置默认策略
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # 基本规则
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 允许LAN到WAN的转发
    iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT
    iptables -A FORWARD -i "$WAN_INTERFACE" -o "$LAN_INTERFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # NAT规则 - 关键配置
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
    iptables -t nat -A POSTROUTING -s "$LAN_NETWORK" -o "$WAN_INTERFACE" -j MASQUERADE
    
    # 允许DHCP服务
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 67 -j ACCEPT
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 68 -j ACCEPT
    
    # 允许DNS查询
    iptables -A INPUT -i "$LAN_INTERFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 53 -j ACCEPT
    
    # 允许Web管理界面
    iptables -A INPUT -i "$LAN_INTERFACE" -p tcp --dport 8080 -j ACCEPT
    
    # 允许SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # 允许ICMP
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT
    
    print_success "NAT转发规则配置完成"
}

# 保存iptables规则
save_iptables() {
    print_info "保存iptables规则..."
    
    # 创建目录
    mkdir -p /etc/router-os
    
    # 保存规则
    iptables-save > /etc/router-os/iptables.rules
    
    # 创建恢复脚本
    cat > /etc/router-os/restore-iptables.sh << 'EOF'
#!/bin/bash
# 恢复iptables规则
iptables-restore < /etc/router-os/iptables.rules
EOF
    chmod +x /etc/router-os/restore-iptables.sh
    
    # 创建systemd服务
    cat > /etc/systemd/system/router-os-iptables.service << EOF
[Unit]
Description=Router OS iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/router-os/restore-iptables.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # 启用服务
    systemctl daemon-reload
    systemctl enable router-os-iptables.service
    
    print_success "iptables规则已保存并设置开机自启"
}

# 配置路由
configure_routing() {
    print_info "配置路由规则..."
    
    # 确保有默认路由通过WAN接口
    # 注意：这里不强制设置默认路由，因为PVE可能已经配置了
    if ! ip route | grep -q "default.*$WAN_INTERFACE"; then
        print_warning "未检测到通过 $WAN_INTERFACE 的默认路由"
        print_info "请确保 $WAN_INTERFACE 接口有正确的默认路由"
        print_info "可以手动添加: ip route add default via <网关IP> dev $WAN_INTERFACE"
    fi
    
    # 添加LAN网络路由（通常不需要，因为接口配置会自动添加）
    if ! ip route | grep -q "$LAN_NETWORK.*$LAN_INTERFACE"; then
        ip route add "$LAN_NETWORK" dev "$LAN_INTERFACE" 2>/dev/null || true
    fi
    
    print_success "路由配置完成"
}

# 显示网络状态
show_network_status() {
    print_info "网络配置状态:"
    echo
    echo "=== 网络接口 ==="
    ip addr show "$WAN_INTERFACE" | grep -E "(inet |state )"
    ip addr show "$LAN_INTERFACE" | grep -E "(inet |state )"
    echo
    echo "=== 路由表 ==="
    ip route show
    echo
    echo "=== NAT规则 ==="
    iptables -t nat -L -n -v
    echo
    echo "=== 转发规则 ==="
    iptables -L FORWARD -n -v
}

# 测试配置
test_configuration() {
    print_info "测试网络配置..."
    
    # 测试IP转发是否启用
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        print_success "IP转发已启用"
    else
        print_error "IP转发未启用"
    fi
    
    # 测试接口状态
    if ip link show "$WAN_INTERFACE" | grep -q "state UP"; then
        print_success "WAN接口 ($WAN_INTERFACE) 状态正常"
    else
        print_warning "WAN接口 ($WAN_INTERFACE) 状态异常"
    fi
    
    if ip link show "$LAN_INTERFACE" | grep -q "state UP"; then
        print_success "LAN接口 ($LAN_INTERFACE) 状态正常"
    else
        print_warning "LAN接口 ($LAN_INTERFACE) 状态异常"
    fi
    
    # 测试LAN接口IP
    if ip addr show "$LAN_INTERFACE" | grep -q "$LAN_IP"; then
        print_success "LAN接口IP配置正确"
    else
        print_error "LAN接口IP配置错误"
    fi
}

# 主函数
main() {
    echo "========================================"
    echo "    PVE Router OS 网络配置脚本"
    echo "========================================"
    echo
    
    check_root
    check_interfaces
    configure_interfaces
    enable_ip_forwarding
    configure_nat
    configure_routing
    save_iptables
    
    echo
    print_success "网络配置完成！"
    echo
    
    show_network_status
    test_configuration
    
    echo
    print_info "接下来的步骤:"
    echo "1. 启用DHCP服务: 修改 config.json 中的 dhcp.enabled 为 true"
    echo "2. 启动Router OS: sudo ./router-os"
    echo "3. 访问Web管理界面: http://$LAN_IP:8080"
    echo "4. 连接客户端到 $LAN_INTERFACE 接口测试"
    echo
    print_warning "如果遇到问题，请检查:"
    echo "- $WAN_INTERFACE 接口是否有正确的IP和默认路由"
    echo "- 防火墙规则是否正确"
    echo "- DHCP客户端是否正确获取到IP地址"
}

# 运行主函数
main "$@"