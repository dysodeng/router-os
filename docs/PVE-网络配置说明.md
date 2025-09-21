# PVE Router OS 网络配置说明

## PVE虚拟化环境概述

本文档详细说明如何在Proxmox VE (PVE)虚拟化环境中配置Router OS，包括网桥设置、虚拟机网络配置、VLAN隔离等内容。

## 网络拓扑

### 基础网络拓扑
```
Internet
    |
[PVE Host] ens18 (物理网卡)
    |
[vmbr0] (Linux Bridge) - PVE管理网络
    |
[vmbr1] (Linux Bridge) - 虚拟机网络
    |
[Router OS VM]
    ├── ens18 (WAN接口) - 连接vmbr0
    └── ens20 (LAN接口) - 连接vmbr1
         |
    [内网设备] - 192.168.2.0/24
```

### 高级网络拓扑（多VLAN环境）
```
Internet
    |
[PVE Host] ens18 (物理网卡，支持VLAN)
    |
[vmbr0] (管理网桥) - VLAN 1 (192.168.1.0/24)
[vmbr1] (WAN网桥) - VLAN 10 (DHCP/静态IP)
[vmbr2] (LAN网桥) - VLAN 20 (192.168.2.0/24)
[vmbr3] (DMZ网桥) - VLAN 30 (192.168.3.0/24)
    |
[Router OS VM]
    ├── ens18 (WAN) - 连接vmbr1
    ├── ens19 (LAN) - 连接vmbr2
    └── ens20 (DMZ) - 连接vmbr3
```

## PVE网桥配置

### 1. 基础网桥配置

#### 通过PVE Web界面配置
1. 登录PVE Web管理界面
2. 选择节点 → 系统 → 网络
3. 创建Linux Bridge

#### vmbr0 (管理网桥)配置
```bash
# /etc/network/interfaces
auto vmbr0
iface vmbr0 inet static
    address 192.168.1.100/24
    gateway 192.168.1.1
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    # PVE管理网络
```

#### vmbr1 (WAN网桥)配置
```bash
# /etc/network/interfaces
auto vmbr1
iface vmbr1 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # 用于Router OS WAN接口
```

#### vmbr2 (LAN网桥)配置
```bash
# /etc/network/interfaces
auto vmbr2
iface vmbr2 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # 用于Router OS LAN接口
```

### 2. VLAN网桥配置

#### 启用VLAN支持
```bash
# 安装VLAN支持
apt update && apt install vlan

# 加载8021q模块
modprobe 8021q
echo "8021q" >> /etc/modules
```

#### VLAN网桥配置示例
```bash
# /etc/network/interfaces

# 物理接口
auto ens18
iface ens18 inet manual

# VLAN 10 - WAN网络
auto ens18.10
iface ens18.10 inet manual
    vlan-raw-device ens18

auto vmbr10
iface vmbr10 inet manual
    bridge-ports ens18.10
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes

# VLAN 20 - LAN网络
auto ens18.20
iface ens18.20 inet manual
    vlan-raw-device ens18

auto vmbr20
iface vmbr20 inet manual
    bridge-ports ens18.20
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes

# VLAN 30 - DMZ网络
auto ens18.30
iface ens18.30 inet manual
    vlan-raw-device ens18

auto vmbr30
iface vmbr30 inet manual
    bridge-ports ens18.30
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
```

### 3. 高级网桥配置

#### 启用VLAN感知网桥
```bash
# 创建VLAN感知网桥
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094
```

#### 网桥性能优化
```bash
# 优化网桥性能
echo 'net.bridge.bridge-nf-call-iptables = 0' >> /etc/sysctl.conf
echo 'net.bridge.bridge-nf-call-ip6tables = 0' >> /etc/sysctl.conf
echo 'net.bridge.bridge-nf-call-arptables = 0' >> /etc/sysctl.conf
sysctl -p
```

## 虚拟机网络配置

### 1. Router OS虚拟机创建

#### 通过PVE Web界面创建虚拟机
1. 登录PVE Web管理界面
2. 点击"创建虚拟机"
3. 配置虚拟机基本信息

#### 虚拟机配置参数
```bash
# 虚拟机基本配置
VM ID: 100
名称: router-os
操作系统: Linux 6.x - 2.6 Kernel
内存: 2048 MB (最小1024MB)
CPU: 2核心
硬盘: 32GB (最小16GB)
网络: 多个网络接口
```

### 2. 网络接口配置

#### 基础双网卡配置
```bash
# 网络设备配置
net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr1,tag=10
net1: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr2,tag=20

# 说明:
# net0: WAN接口，连接到vmbr1网桥，VLAN 10
# net1: LAN接口，连接到vmbr2网桥，VLAN 20
```

#### 多网卡配置（企业环境）
```bash
# 多网络接口配置
net0: virtio=XX:XX:XX:XX:XX:01,bridge=vmbr1,tag=10    # WAN
net1: virtio=XX:XX:XX:XX:XX:02,bridge=vmbr2,tag=20    # LAN
net2: virtio=XX:XX:XX:XX:XX:03,bridge=vmbr3,tag=30    # DMZ
net3: virtio=XX:XX:XX:XX:XX:04,bridge=vmbr4,tag=40    # Guest WiFi
```

### 3. 虚拟机配置文件

#### /etc/pve/qemu-server/100.conf 示例
```bash
# Router OS虚拟机配置文件
agent: 1
balloon: 0
bios: ovmf
boot: order=scsi0;ide2;net0
cores: 2
cpu: host
efidisk0: local-lvm:vm-100-disk-0,efitype=4m,pre-enrolled-keys=1,size=4M
ide2: local:iso/ubuntu-22.04.3-live-server-amd64.iso,media=cdrom,size=1382184K
machine: pc-q35-7.2
memory: 2048
meta: creation-qemu=7.2.0,ctime=1699123456
name: router-os
net0: virtio=BC:24:11:XX:XX:01,bridge=vmbr1,firewall=1,tag=10
net1: virtio=BC:24:11:XX:XX:02,bridge=vmbr2,firewall=1,tag=20
numa: 0
ostype: l26
scsi0: local-lvm:vm-100-disk-1,iothread=1,size=32G
scsihw: virtio-scsi-pci
smbios1: uuid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
sockets: 1
startup: order=1,up=30
vmgenid: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

### 4. 网络接口映射

#### 虚拟机内部接口识别
```bash
# 查看网络接口
ip link show

# 典型输出:
# 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
# 2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500  # WAN接口
# 3: ens19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500  # LAN接口
# 4: ens20: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500  # DMZ接口
```

#### 接口配置脚本
```bash
#!/bin/bash
# /etc/network/interfaces 配置

# WAN接口 (ens18)
auto ens18
iface ens18 inet dhcp
    # 或静态IP配置
    # iface ens18 inet static
    # address 192.168.1.100/24
    # gateway 192.168.1.1

# LAN接口 (ens19)
auto ens19
iface ens19 inet static
    address 192.168.2.1/24

# DMZ接口 (ens20) - 可选
auto ens20
iface ens20 inet static
    address 192.168.3.1/24
```

### 5. 高可用性配置

#### 虚拟机自动启动
```bash
# 设置虚拟机开机自启
qm set 100 --startup order=1,up=30,down=60

# 参数说明:
# order=1: 启动顺序（数字越小越早启动）
# up=30: 启动后等待30秒再启动下一个VM
# down=60: 关机时等待60秒
```

#### 资源限制和优化
```bash
# CPU配置
qm set 100 --cores 2 --cpu host --numa 1

# 内存配置
qm set 100 --memory 2048 --balloon 0

# 磁盘IO优化
qm set 100 --scsi0 local-lvm:vm-100-disk-1,iothread=1,cache=writeback

# 网络优化
qm set 100 --net0 virtio,bridge=vmbr1,queues=4
```

### 6. 网络性能优化

#### 启用多队列网络
```bash
# 在虚拟机配置中启用多队列
net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr1,queues=4
net1: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr2,queues=4

# 虚拟机内部优化
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
sysctl -p
```

#### SR-IOV配置（高性能需求）
```bash
# 启用SR-IOV（需要硬件支持）
# 在PVE主机上配置
echo 'intel_iommu=on' >> /etc/default/grub
echo 'iommu=pt' >> /etc/default/grub
update-grub
reboot

# 创建VF（虚拟功能）
echo 4 > /sys/class/net/ens18/device/sriov_numvfs

# 分配VF给虚拟机
qm set 100 --hostpci0 01:10.0,pcie=1
```

## 配置步骤

### 1. 运行网络配置脚本

```bash
# 给脚本执行权限
chmod +x deploy/setup-pve-network.sh

# 运行配置脚本（需要root权限）
sudo ./deploy/setup-pve-network.sh
```

这个脚本会自动完成：
- 配置网络接口（ens18为WAN，ens20为LAN）
- 启用IP转发
- 配置NAT转发规则
- 设置防火墙规则
- 保存配置并设置开机自启

### 2. 启动Router OS服务

```bash
# 编译并运行
go build -o router-os ./cmd/router && sudo ./router-os
```

### 3. 访问Web管理界面

打开浏览器访问：`http://192.168.2.1:8080`
- 用户名：admin
- 密码：admin123

#### Web管理界面功能
- **仪表板**: 查看系统状态、网络流量、连接数等实时信息
- **路由管理**: 查看和管理路由表、添加/删除静态路由
- **接口管理**: 监控网络接口状态、配置接口参数
- **防火墙**: 配置防火墙规则、查看连接状态
- **DHCP管理**: 管理DHCP服务器、查看租约信息
- **VPN服务器**: 配置和管理VPN连接
- **QoS流量控制**: 设置带宽限制和流量优先级
- **数据包捕获**: 实时监控和分析网络流量
- **系统监控**: 查看系统性能、日志和统计信息

## 网络配置详解

### 接口配置
- **ens18 (WAN接口)**: 连接到外网，由PVE自动配置DHCP或静态IP
- **ens20 (LAN接口)**: 内网接口，IP地址：192.168.2.1/24

### DHCP配置
- **IP范围**: 192.168.2.100 - 192.168.2.200
- **网关**: 192.168.2.1
- **DNS服务器**: 8.8.8.8, 8.8.4.4
- **租约时间**: 24小时

### 防火墙配置
- **默认策略**: DROP（拒绝所有未明确允许的流量）
- **允许规则**: SSH(22)、HTTP(80)、HTTPS(443)、Web管理(8080)
- **NAT规则**: 自动配置内网到外网的地址转换

### VPN服务器配置
- **协议**: OpenVPN
- **端口**: 1194 (UDP)
- **网络**: 10.8.0.0/24
- **加密**: AES-256-CBC

### QoS流量控制
- **总带宽**: 根据WAN接口自动检测
- **优先级队列**: 高优先级(SSH、VPN)、普通优先级(HTTP/HTTPS)、低优先级(P2P)
- **带宽分配**: 高优先级30%、普通优先级50%、低优先级20%

### NAT转发规则
系统会自动配置以下iptables规则：

```bash
# 启用NAT转发
iptables -t nat -A POSTROUTING -o ens18 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o ens18 -j MASQUERADE

# 允许转发
iptables -A FORWARD -i ens20 -o ens18 -j ACCEPT
iptables -A FORWARD -i ens18 -o ens20 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

## 工作原理

1. **客户端连接**: 客户端连接到ens20接口
2. **DHCP分配**: Router OS的DHCP服务为客户端分配192.168.2.x的IP地址
3. **数据包转发**: 客户端发送的数据包通过ens20进入Router OS
4. **NAT转换**: iptables将源IP从192.168.2.x转换为ens18的IP地址
5. **外网访问**: 转换后的数据包通过ens18发送到外网
6. **响应返回**: 外网响应通过ens18返回，再经过NAT转换发送给客户端

## VLAN配置和网络隔离

### 1. VLAN基础概念

#### VLAN的作用
- **网络隔离**: 将物理网络分割为多个逻辑网络
- **安全性**: 不同VLAN之间默认无法通信
- **灵活性**: 可以跨物理设备组建逻辑网络
- **性能优化**: 减少广播域，提高网络性能

#### VLAN标签范围
```bash
# VLAN ID范围
VLAN 1: 默认VLAN（通常用于管理）
VLAN 2-1001: 标准VLAN范围
VLAN 1002-1005: 保留VLAN
VLAN 1006-4094: 扩展VLAN范围
```

### 2. PVE中的VLAN配置

#### 启用VLAN感知网桥
```bash
# 修改 /etc/network/interfaces
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094
```

#### 创建VLAN子接口
```bash
# 方法1: 传统VLAN配置
auto ens18.10
iface ens18.10 inet manual
    vlan-raw-device ens18

auto vmbr10
iface vmbr10 inet manual
    bridge-ports ens18.10
    bridge-stp off
    bridge-fd 0

# 方法2: VLAN感知网桥（推荐）
auto vmbr0
iface vmbr0 inet manual
    bridge-ports ens18
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 10,20,30,40
```

### 3. 虚拟机VLAN配置

#### 单VLAN配置
```bash
# 虚拟机网络接口配置
net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0,tag=10

# 说明:
# tag=10: 将此接口分配到VLAN 10
# 虚拟机内部看到的是untagged流量
```

#### 多VLAN配置
```bash
# Router OS虚拟机多VLAN配置
net0: virtio=XX:XX:XX:XX:XX:01,bridge=vmbr0,tag=10    # 管理VLAN
net1: virtio=XX:XX:XX:XX:XX:02,bridge=vmbr0,tag=20    # 用户VLAN
net2: virtio=XX:XX:XX:XX:XX:03,bridge=vmbr0,tag=30    # 服务器VLAN
net3: virtio=XX:XX:XX:XX:XX:04,bridge=vmbr0,tag=40    # 访客VLAN
```

#### Trunk端口配置
```bash
# 允许虚拟机处理多个VLAN（Trunk模式）
net0: virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0,trunks=10;20;30;40

# 虚拟机内部需要配置VLAN子接口
# 在Router OS中配置:
ip link add link ens18 name ens18.10 type vlan id 10
ip link add link ens18 name ens18.20 type vlan id 20
ip link add link ens18 name ens18.30 type vlan id 30
ip link add link ens18 name ens18.40 type vlan id 40
```

### 4. 网络隔离策略

#### 基础隔离配置
```bash
# VLAN间路由控制（在Router OS中配置）
# 默认拒绝所有VLAN间通信
iptables -A FORWARD -j DROP

# 允许特定VLAN间通信
iptables -A FORWARD -i ens18.10 -o ens18.20 -j ACCEPT  # 管理到用户
iptables -A FORWARD -i ens18.20 -o ens18.30 -j ACCEPT  # 用户到服务器
iptables -A FORWARD -i ens18.30 -o ens18.20 -m state --state ESTABLISHED,RELATED -j ACCEPT
```

#### 高级隔离策略
```json
{
  "vlan_policies": {
    "management_vlan": {
      "vlan_id": 10,
      "subnet": "192.168.10.0/24",
      "access_rules": [
        "allow_all_outbound",
        "allow_ssh_inbound",
        "allow_web_management"
      ]
    },
    "user_vlan": {
      "vlan_id": 20,
      "subnet": "192.168.20.0/24",
      "access_rules": [
        "allow_internet",
        "deny_management",
        "allow_dns",
        "allow_dhcp"
      ]
    },
    "server_vlan": {
      "vlan_id": 30,
      "subnet": "192.168.30.0/24",
      "access_rules": [
        "allow_from_user_vlan",
        "deny_internet_direct",
        "allow_management_access"
      ]
    },
    "guest_vlan": {
      "vlan_id": 40,
      "subnet": "192.168.40.0/24",
      "access_rules": [
        "allow_internet_only",
        "deny_all_internal",
        "time_based_access"
      ]
    }
  }
}
```

### 5. 微分段和零信任网络

#### 微分段配置
```bash
# 基于应用的网络分段
# Web服务器分段
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.10 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.10 -p tcp --dport 443 -j ACCEPT

# 数据库服务器分段
iptables -A FORWARD -s 192.168.30.10 -d 192.168.30.20 -p tcp --dport 3306 -j ACCEPT

# 文件服务器分段
iptables -A FORWARD -s 192.168.20.0/24 -d 192.168.30.30 -p tcp --dport 445 -j ACCEPT
```

#### 零信任网络实现
```bash
# 默认拒绝所有流量
iptables -P FORWARD DROP

# 基于身份的访问控制
# 需要结合认证系统实现
# 示例: 基于MAC地址的访问控制
iptables -A FORWARD -m mac --mac-source AA:BB:CC:DD:EE:FF -j ACCEPT

# 基于时间的访问控制
iptables -A FORWARD -m time --timestart 09:00 --timestop 18:00 --weekdays Mon,Tue,Wed,Thu,Fri -j ACCEPT
```

### 6. VLAN监控和管理

#### VLAN状态监控
```bash
# 查看VLAN配置
bridge vlan show

# 查看网桥VLAN信息
cat /sys/class/net/vmbr0/bridge/vlan_filtering

# 监控VLAN流量
tcpdump -i vmbr0 vlan 10

# 查看VLAN统计信息
cat /proc/net/vlan/ens18.10
```

#### 动态VLAN管理
```bash
# 动态添加VLAN
bridge vlan add vid 50 dev vmbr0 self
bridge vlan add vid 50 dev ens18

# 动态删除VLAN
bridge vlan del vid 50 dev vmbr0 self
bridge vlan del vid 50 dev ens18

# 修改虚拟机VLAN（需要重启网络接口）
qm set 100 --net0 virtio=XX:XX:XX:XX:XX:XX,bridge=vmbr0,tag=50
```

### 7. 网络安全最佳实践

#### VLAN安全配置
```bash
# 禁用不必要的VLAN
bridge vlan del vid 1 dev vmbr0 self  # 删除默认VLAN

# 启用VLAN过滤
echo 1 > /sys/class/net/vmbr0/bridge/vlan_filtering

# 配置PVID（Port VLAN ID）
bridge vlan add vid 999 dev vmbr0 pvid untagged self  # 管理VLAN
```

#### 访问控制列表
```bash
# 基于源/目标的ACL
iptables -A FORWARD -s 192.168.10.0/24 -d 192.168.20.0/24 -j DROP
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.10.0/24 -j DROP
iptables -A FORWARD -s 192.168.40.0/24 -d 192.168.30.0/24 -j DROP

# 基于协议的ACL
iptables -A FORWARD -p icmp -j DROP  # 禁用ping
iptables -A FORWARD -p tcp --dport 23 -j DROP  # 禁用telnet
iptables -A FORWARD -p tcp --dport 21 -j DROP  # 禁用FTP
```

## 故障排除

### 1. PVE网桥问题诊断

#### 检查网桥状态
```bash
# 查看所有网桥
brctl show

# 查看网桥详细信息
ip link show type bridge

# 检查网桥是否启用
cat /sys/class/net/vmbr0/operstate

# 查看网桥端口
bridge link show

# 检查VLAN过滤状态
cat /sys/class/net/vmbr0/bridge/vlan_filtering
```

#### 网桥连通性测试
```bash
# 测试网桥内部连通性
ping -I vmbr0 192.168.1.1

# 检查网桥MAC地址表
bridge fdb show br vmbr0

# 监控网桥流量
tcpdump -i vmbr0 -n

# 查看网桥统计信息
cat /sys/class/net/vmbr0/statistics/rx_packets
cat /sys/class/net/vmbr0/statistics/tx_packets
```

### 2. 虚拟机网络问题

#### 虚拟机网络接口检查
```bash
# 在PVE主机上检查虚拟机网络配置
qm config 100 | grep net

# 查看虚拟机网络接口状态
qm monitor 100
(qemu) info network

# 检查虚拟机网络设备
ls -la /sys/class/net/tap*
```

#### 虚拟机内部网络诊断
```bash
# 在虚拟机内部执行
# 检查网络接口状态
ip addr show ens18
ip addr show ens19

# 检查网络接口统计
cat /proc/net/dev

# 检查网络驱动
lsmod | grep virtio
dmesg | grep virtio

# 测试网络性能
iperf3 -s  # 在服务器端
iperf3 -c 192.168.2.1  # 在客户端
```

### 3. VLAN问题诊断

#### VLAN配置检查
```bash
# 查看VLAN配置
bridge vlan show

# 检查VLAN接口
ip link show type vlan

# 查看VLAN统计
cat /proc/net/vlan/config

# 测试VLAN连通性
ping -I ens18.10 192.168.10.1
```

#### VLAN流量分析
```bash
# 捕获特定VLAN流量
tcpdump -i vmbr0 vlan 10 and host 192.168.10.100

# 查看VLAN标签
tcpdump -i vmbr0 -e vlan

# 监控VLAN间路由
tcpdump -i any host 192.168.10.100 and host 192.168.20.100
```

### 4. 性能问题诊断

#### 网络性能监控
```bash
# 查看网络接口带宽使用
iftop -i vmbr0

# 监控网络连接
ss -tuln

# 查看网络缓冲区
cat /proc/sys/net/core/rmem_max
cat /proc/sys/net/core/wmem_max

# 检查网络队列
tc qdisc show dev vmbr0
```

#### 虚拟化性能优化
```bash
# 检查CPU使用率
top -p $(pgrep qemu)

# 查看虚拟机IO统计
qm monitor 100
(qemu) info blockstats

# 检查内存使用
cat /proc/$(pgrep qemu)/status | grep Vm

# 优化网络参数
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
sysctl -p
```

### 5. 常见问题解决方案

#### 问题1: 虚拟机无法获取网络连接
```bash
# 检查步骤:
1. 确认网桥配置正确
   brctl show vmbr0
   
2. 检查虚拟机网络配置
   qm config 100 | grep net
   
3. 重启网络服务
   systemctl restart networking
   
4. 重新配置虚拟机网络
   qm set 100 --net0 virtio,bridge=vmbr0
```

#### 问题2: VLAN间无法通信
```bash
# 解决步骤:
1. 检查VLAN配置
   bridge vlan show
   
2. 确认路由配置
   ip route show table all
   
3. 检查防火墙规则
   iptables -L FORWARD -v
   
4. 启用VLAN间路由
   echo 1 > /proc/sys/net/ipv4/ip_forward
```

#### 问题3: 网络性能差
```bash
# 优化步骤:
1. 启用多队列网络
   qm set 100 --net0 virtio,bridge=vmbr0,queues=4
   
2. 优化网络缓冲区
   echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
   echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
   
3. 使用SR-IOV（如果硬件支持）
   echo 4 > /sys/class/net/ens18/device/sriov_numvfs
   
4. 调整CPU亲和性
   qm set 100 --vcpus 2 --cpuunits 2048
```

### 6. 高级诊断工具

#### 网络流量分析
```bash
# 安装分析工具
apt install wireshark-common tshark nload iftop

# 实时流量监控
nload vmbr0

# 详细协议分析
tshark -i vmbr0 -f "host 192.168.2.100"

# 网络延迟测试
mtr 8.8.8.8

# 带宽测试
iperf3 -c speedtest.net -p 5201
```

#### 系统级网络诊断
```bash
# 检查网络命名空间
ip netns list

# 查看网络设备详细信息
ethtool ens18

# 检查网络驱动信息
modinfo virtio_net

# 查看PCI设备
lspci | grep -i network

# 检查中断分布
cat /proc/interrupts | grep virtio
```

### 7. 日志分析

#### 系统日志检查
```bash
# 查看网络相关日志
journalctl -u networking
journalctl -u systemd-networkd

# 查看内核网络日志
dmesg | grep -i network
dmesg | grep -i virtio

# 查看PVE日志
tail -f /var/log/pve/tasks/active

# 查看虚拟机日志
tail -f /var/log/qemu-server/100.log
```

#### 网络事件监控
```bash
# 监控网络接口状态变化
ip monitor link

# 监控路由变化
ip monitor route

# 监控邻居表变化
ip monitor neigh

# 实时网络连接监控
watch -n 1 'ss -tuln | wc -l'
```

### 8. 基础网络检查

#### 检查网络接口状态
```bash
ip addr show ens18
ip addr show ens19
ip addr show ens20
```

#### 检查路由表
```bash
ip route show
ip route show table all
```

#### 检查NAT规则
```bash
sudo iptables -t nat -L -n -v
sudo iptables -t mangle -L -n -v
```

#### 检查转发规则
```bash
sudo iptables -L FORWARD -n -v
sudo iptables -L INPUT -n -v
sudo iptables -L OUTPUT -n -v
```

#### 检查IP转发是否启用
```bash
cat /proc/sys/net/ipv4/ip_forward
# 应该返回 1

# 检查IPv6转发
cat /proc/sys/net/ipv6/conf/all/forwarding
```

#### 测试连通性
```bash
# 从Router OS测试外网连通性
ping 8.8.8.8
ping6 2001:4860:4860::8888

# 从客户端测试（获取DHCP IP后）
ping 192.168.2.1  # 测试到网关
ping 8.8.8.8      # 测试外网

# 测试DNS解析
nslookup google.com
dig @8.8.8.8 google.com

# 测试端口连通性
telnet 192.168.2.1 8080
nc -zv 192.168.2.1 22
```

## 常见问题

### Q: 客户端无法获取IP地址
A: 检查：
1. DHCP服务是否启用（config.json中dhcp.enabled = true）
2. ens20接口是否正确配置IP地址
3. 防火墙是否允许DHCP流量（UDP 67/68端口）

### Q: 客户端能获取IP但无法上网
A: 检查：
1. IP转发是否启用
2. NAT规则是否正确配置
3. ens18接口是否有外网连接
4. 默认路由是否正确

### Q: Web管理界面无法访问
A: 检查：
1. Router OS服务是否正常运行
2. 防火墙是否允许8080端口
3. 客户端IP是否在正确的网段

## 高级配置

### 端口转发
如果需要将外网流量转发到内网服务器，可以添加DNAT规则：

```bash
# 例：将外网80端口转发到内网192.168.2.100:80
iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to-destination 192.168.2.100:80
iptables -A FORWARD -i ens18 -o ens20 -p tcp --dport 80 -d 192.168.2.100 -j ACCEPT
```

也可以通过Web管理界面的端口转发页面进行配置：
1. 访问 `http://192.168.2.1:8080/ports`
2. 点击"添加端口转发规则"
3. 填写外部端口、内部IP和端口
4. 选择协议类型（TCP/UDP）
5. 保存配置

### 防火墙规则管理
通过Web管理界面配置防火墙规则：

1. **访问控制**: 控制特定IP或网段的访问权限
2. **端口过滤**: 开放或关闭特定端口
3. **协议限制**: 限制特定协议的使用
4. **时间策略**: 设置基于时间的访问控制

#### 常用防火墙规则示例
```json
{
  "firewall": {
    "rules": [
      {
        "id": "allow_web",
        "action": "ACCEPT",
        "protocol": "tcp",
        "dst_port": [80, 443],
        "description": "允许Web访问"
      },
      {
        "id": "block_p2p",
        "action": "DROP",
        "protocol": "tcp",
        "dst_port": [6881, 6999],
        "description": "阻止P2P流量"
      }
    ]
  }
}
```

### VPN服务器配置
配置OpenVPN服务器：

1. **生成证书**: 系统自动生成CA证书和服务器证书
2. **客户端管理**: 添加/删除VPN客户端
3. **网络配置**: 设置VPN网段和路由
4. **安全设置**: 配置加密算法和认证方式

#### VPN客户端配置示例
```bash
# 通过CLI添加VPN客户端
vpn add client client1 --email user@example.com

# 生成客户端配置文件
vpn export config client1 > client1.ovpn

# 查看VPN连接状态
vpn show connections
```

### QoS流量控制
配置服务质量控制：

1. **带宽分配**: 为不同类型的流量分配带宽
2. **优先级设置**: 设置流量优先级
3. **流量整形**: 控制突发流量
4. **队列管理**: 配置不同的队列策略

#### QoS配置示例
```json
{
  "qos": {
    "enabled": true,
    "total_bandwidth": "100Mbps",
    "classes": [
      {
        "name": "high_priority",
        "bandwidth": "30%",
        "priority": 1,
        "protocols": ["ssh", "vpn"]
      },
      {
        "name": "normal",
        "bandwidth": "50%",
        "priority": 2,
        "protocols": ["http", "https"]
      },
      {
        "name": "low_priority",
        "bandwidth": "20%",
        "priority": 3,
        "protocols": ["p2p", "ftp"]
      }
    ]
  }
}
```

### 数据包捕获和分析
启用网络流量监控：

1. **实时捕获**: 监控指定接口的网络流量
2. **协议分析**: 分析不同协议的流量分布
3. **流量统计**: 查看带宽使用情况
4. **异常检测**: 识别异常网络行为

#### 捕获配置示例
```bash
# 开始捕获ens20接口的流量
capture start ens20 --filter "tcp port 80"

# 查看流量统计
capture stats protocol
capture stats top-talkers

# 导出捕获数据
capture export ens20 /tmp/traffic.pcap
```

### 数据库配置
Router OS使用SQLite数据库存储配置和状态信息：

- **配置数据**: 路由表、接口配置、防火墙规则
- **状态信息**: DHCP租约、VPN连接、流量统计
- **日志记录**: 系统日志、访问日志、错误日志

#### 数据库维护
```bash
# 查看数据库状态
show database status

# 备份数据库
database backup /tmp/router-backup.db

# 恢复数据库
database restore /tmp/router-backup.db

# 清理旧数据
database cleanup --days 30
```