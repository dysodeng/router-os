# PVE Router OS 网络配置说明

## 网络拓扑

```
Internet
    |
[PVE Host] ens18 (外网接口)
    |
[Router OS VM]
    |
    ens20 (内网接口/LAN) - 192.168.2.1/24
    |
[DHCP客户端] - 192.168.2.100-200
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

## 网络配置详解

### 接口配置
- **ens18 (WAN接口)**: 连接到外网，由PVE自动配置DHCP或静态IP
- **ens20 (LAN接口)**: 内网接口，IP地址：192.168.2.1/24

### DHCP配置
- **IP范围**: 192.168.2.100 - 192.168.2.200
- **网关**: 192.168.2.1
- **DNS服务器**: 8.8.8.8, 8.8.4.4
- **租约时间**: 24小时

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

## 故障排除

### 检查网络接口状态
```bash
ip addr show ens18
ip addr show ens20
```

### 检查路由表
```bash
ip route show
```

### 检查NAT规则
```bash
sudo iptables -t nat -L -n -v
```

### 检查转发规则
```bash
sudo iptables -L FORWARD -n -v
```

### 检查IP转发是否启用
```bash
cat /proc/sys/net/ipv4/ip_forward
# 应该返回 1
```

### 测试连通性
```bash
# 从Router OS测试外网连通性
ping 8.8.8.8

# 从客户端测试（获取DHCP IP后）
ping 192.168.2.1  # 测试到网关
ping 8.8.8.8      # 测试外网
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

### 带宽限制
可以通过QoS功能限制客户端带宽，在Web管理界面的QoS页面进行配置。

### 防火墙规则
可以在Web管理界面的防火墙页面添加自定义规则，控制客户端的网络访问。