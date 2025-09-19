#!/bin/bash

# Router OS 网络配置脚本
# 用于配置网络接口和路由规则

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# 检查网络工具
check_network_tools() {
    print_info "检查网络工具..."
    
    local required_tools=("ip" "iptables" "sysctl")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "未找到必需的工具: $tool"
            print_info "请安装: apt-get install iproute2 iptables procps (Ubuntu/Debian)"
            print_info "或: yum install iproute2 iptables procps-ng (CentOS/RHEL)"
            exit 1
        fi
    done
    
    print_success "网络工具检查完成"
}

# 启用IP转发
enable_ip_forwarding() {
    print_info "启用IP转发..."
    
    # 临时启用
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    
    # 永久启用
    cat > /etc/sysctl.d/99-router-os-forwarding.conf << EOF
# Router OS IP转发配置
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# 优化网络性能
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000

# 防止IP欺骗
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 忽略ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 忽略源路由
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
    
    # 应用配置
    sysctl -p /etc/sysctl.d/99-router-os-forwarding.conf
    
    print_success "IP转发已启用"
}

# 配置防火墙规则
configure_firewall() {
    print_info "配置基本防火墙规则..."
    
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
    
    # 允许回环接口
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 允许SSH (端口22)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # 允许ICMP
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT
    
    # 允许路由协议端口
    # RIP (UDP 520)
    iptables -A INPUT -p udp --dport 520 -j ACCEPT
    iptables -A OUTPUT -p udp --dport 520 -j ACCEPT
    
    # OSPF (协议89)
    iptables -A INPUT -p 89 -j ACCEPT
    iptables -A OUTPUT -p 89 -j ACCEPT
    
    # BGP (TCP 179)
    iptables -A INPUT -p tcp --dport 179 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 179 -j ACCEPT
    
    # IS-IS (协议124)
    iptables -A INPUT -p 124 -j ACCEPT
    iptables -A OUTPUT -p 124 -j ACCEPT
    
    print_success "防火墙规则配置完成"
}

# 保存防火墙规则
save_firewall_rules() {
    print_info "保存防火墙规则..."
    
    # 检测系统类型并保存规则
    if command -v iptables-save &> /dev/null; then
        if [[ -d /etc/iptables ]]; then
            # Debian/Ubuntu
            iptables-save > /etc/iptables/rules.v4
            print_info "规则已保存到 /etc/iptables/rules.v4"
        elif [[ -f /etc/sysconfig/iptables ]]; then
            # CentOS/RHEL
            iptables-save > /etc/sysconfig/iptables
            print_info "规则已保存到 /etc/sysconfig/iptables"
        else
            # 通用保存位置
            mkdir -p /etc/router-os
            iptables-save > /etc/router-os/iptables.rules
            print_info "规则已保存到 /etc/router-os/iptables.rules"
            
            # 创建恢复脚本
            cat > /etc/router-os/restore-iptables.sh << 'EOF'
#!/bin/bash
# 恢复iptables规则
iptables-restore < /etc/router-os/iptables.rules
EOF
            chmod +x /etc/router-os/restore-iptables.sh
            print_info "创建了恢复脚本: /etc/router-os/restore-iptables.sh"
        fi
    fi
    
    print_success "防火墙规则保存完成"
}

# 创建网络接口配置示例
create_interface_examples() {
    print_info "创建网络接口配置示例..."
    
    mkdir -p /etc/router-os/examples
    
    # 创建静态IP配置示例
    cat > /etc/router-os/examples/static-interface.conf << 'EOF'
# 静态IP接口配置示例
# 使用方法: ip addr add 192.168.1.1/24 dev eth0

# 主接口配置
auto eth0
iface eth0 inet static
    address 192.168.1.1
    netmask 255.255.255.0
    network 192.168.1.0
    broadcast 192.168.1.255

# 辅助接口配置
auto eth1
iface eth1 inet static
    address 10.0.0.1
    netmask 255.255.255.0
    network 10.0.0.0
    broadcast 10.0.0.255
EOF

    # 创建VLAN配置示例
    cat > /etc/router-os/examples/vlan-interface.conf << 'EOF'
# VLAN接口配置示例
# 需要安装vlan包: apt-get install vlan

# 加载8021q模块
modprobe 8021q

# 创建VLAN接口
vconfig add eth0 100
vconfig add eth0 200

# 配置VLAN接口
ip addr add 192.168.100.1/24 dev eth0.100
ip addr add 192.168.200.1/24 dev eth0.200

# 启用接口
ip link set dev eth0.100 up
ip link set dev eth0.200 up
EOF

    # 创建桥接配置示例
    cat > /etc/router-os/examples/bridge-interface.conf << 'EOF'
# 桥接接口配置示例
# 需要安装bridge-utils: apt-get install bridge-utils

# 创建桥接接口
brctl addbr br0

# 添加接口到桥
brctl addif br0 eth0
brctl addif br0 eth1

# 配置桥接口
ip addr add 192.168.1.1/24 dev br0

# 启用桥接口
ip link set dev br0 up

# 启用STP (可选)
brctl stp br0 on
EOF

    print_success "网络接口配置示例创建完成"
    print_info "示例文件位置: /etc/router-os/examples/"
}

# 检查网络接口状态
check_interfaces() {
    print_info "检查网络接口状态..."
    
    echo "可用的网络接口:"
    ip link show | grep -E "^[0-9]+:" | while read line; do
        interface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        state=$(echo "$line" | grep -o "state [A-Z]*" | cut -d' ' -f2)
        echo "  - $interface ($state)"
    done
    
    echo
    echo "接口IP地址:"
    ip addr show | grep -E "inet " | while read line; do
        echo "  $line"
    done
    
    print_success "网络接口检查完成"
}

# 测试网络连通性
test_connectivity() {
    print_info "测试网络连通性..."
    
    # 测试本地回环
    if ping -c 1 127.0.0.1 &> /dev/null; then
        print_success "本地回环测试通过"
    else
        print_error "本地回环测试失败"
    fi
    
    # 测试外网连通性（如果有默认路由）
    if ip route | grep -q "default"; then
        if ping -c 1 8.8.8.8 &> /dev/null; then
            print_success "外网连通性测试通过"
        else
            print_warning "外网连通性测试失败（可能是正常的）"
        fi
    else
        print_info "未配置默认路由，跳过外网测试"
    fi
}

# 显示配置后信息
show_post_config_info() {
    print_success "网络配置完成！"
    echo
    print_info "配置信息:"
    echo "  - IP转发: 已启用"
    echo "  - 防火墙: 已配置基本规则"
    echo "  - 配置文件: /etc/sysctl.d/99-router-os-forwarding.conf"
    echo "  - 示例配置: /etc/router-os/examples/"
    echo
    print_info "下一步:"
    echo "  1. 根据需要配置网络接口IP地址"
    echo "  2. 修改 /opt/router-os/config.json 中的接口配置"
    echo "  3. 重启Router OS服务: systemctl restart router-os"
    echo
    print_info "常用网络命令:"
    echo "  - 查看接口: ip link show"
    echo "  - 查看IP: ip addr show"
    echo "  - 查看路由: ip route show"
    echo "  - 配置IP: ip addr add 192.168.1.1/24 dev eth0"
    echo "  - 启用接口: ip link set eth0 up"
}

# 重置网络配置
reset_network() {
    print_info "重置网络配置..."
    
    # 清除防火墙规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # 设置默认策略为ACCEPT
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # 删除配置文件
    rm -f /etc/sysctl.d/99-router-os-forwarding.conf
    
    # 重新加载sysctl
    sysctl --system
    
    print_success "网络配置已重置"
}

# 主函数
main() {
    echo "========================================"
    echo "       Router OS 网络配置脚本"
    echo "========================================"
    echo
    
    case "${1:-setup}" in
        "setup")
            check_root
            check_network_tools
            enable_ip_forwarding
            configure_firewall
            save_firewall_rules
            create_interface_examples
            check_interfaces
            test_connectivity
            show_post_config_info
            ;;
        "reset")
            check_root
            reset_network
            ;;
        "check")
            check_interfaces
            test_connectivity
            ;;
        "help"|"-h"|"--help")
            echo "用法: $0 [setup|reset|check|help]"
            echo
            echo "命令:"
            echo "  setup  配置网络环境 (默认)"
            echo "  reset  重置网络配置"
            echo "  check  检查网络状态"
            echo "  help   显示此帮助信息"
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