# Router OS 用户使用手册

## 📋 目录

1. [安装和启动](#安装和启动)
2. [Web管理界面](#web管理界面)
3. [配置文件详解](#配置文件详解)
4. [CLI 命令参考](#cli-命令参考)
5. [路由管理](#路由管理)
6. [接口管理](#接口管理)
7. [协议配置](#协议配置)
8. [防火墙管理](#防火墙管理)
9. [DHCP服务器](#dhcp服务器)
10. [VPN服务器](#vpn服务器)
11. [QoS流量控制](#qos流量控制)
12. [数据包捕获](#数据包捕获)
13. [监控和诊断](#监控和诊断)
14. [常用操作示例](#常用操作示例)
15. [配置模板](#配置模板)
16. [命令速查表](#命令速查表)

---

## 🚀 安装和启动

### 系统要求

- Go 1.19+
- Linux/macOS/Windows
- 管理员权限（推荐）

### 安装步骤

```bash
# 1. 进入项目目录
cd router-os

# 2. 初始化模块
go mod init router-os
go mod tidy

# 3. 构建项目
go build -o router-os main.go

# 4. 运行路由器
./router-os

# 或者直接运行
go run main.go
```

### 启动选项

```bash
# 指定配置文件
./router-os -config /path/to/config.json

# 指定日志级别
./router-os -log-level debug

# 后台运行
nohup ./router-os > router.log 2>&1 &
```

---

## 🌐 Web管理界面

### 访问Web界面

启动路由器后，可以通过Web浏览器访问管理界面：

```
http://localhost:8080
```

### 认证登录

Web界面使用基本认证（Basic Authentication）：

- **默认用户名**: `admin`
- **默认密码**: `admin123`

> ⚠️ **安全提示**: 首次使用时请立即修改默认密码！

### 主要功能模块

#### 1. 仪表板 (Dashboard)

- **系统概览**: 显示系统运行状态、运行时间、内存使用等
- **接口状态**: 实时显示所有网络接口的状态和统计信息
- **路由统计**: 显示路由表大小、路由类型分布
- **流量监控**: 实时显示网络流量图表

访问地址: `http://localhost:8080/dashboard`

#### 2. 路由管理

- **路由表查看**: 查看所有路由条目
- **静态路由管理**: 添加、编辑、删除静态路由
- **动态路由监控**: 查看RIP等协议学习的路由
- **路由策略配置**: 配置路由过滤和策略

访问地址: `http://localhost:8080/routes`

**操作示例**:
```bash
# 添加静态路由
POST /api/routes
{
  "destination": "192.168.2.0/24",
  "gateway": "192.168.1.2",
  "interface": "eth0",
  "metric": 1
}

# 删除路由
DELETE /api/routes/192.168.2.0%2F24
```

#### 3. 接口管理

- **接口配置**: 配置IP地址、子网掩码、MTU等
- **接口状态**: 启用/禁用接口
- **统计信息**: 查看接口流量统计
- **接口监控**: 实时监控接口状态变化

访问地址: `http://localhost:8080/interfaces`

#### 4. 防火墙管理

- **规则管理**: 添加、编辑、删除防火墙规则
- **访问控制**: 配置允许/拒绝规则
- **端口管理**: 配置端口转发和映射
- **安全策略**: 配置安全策略和访问控制列表

访问地址: `http://localhost:8080/firewall`

#### 5. DHCP服务器

- **DHCP配置**: 配置IP地址池、租约时间
- **客户端管理**: 查看和管理DHCP客户端
- **静态绑定**: 配置MAC地址和IP地址的静态绑定
- **租约监控**: 监控DHCP租约状态

访问地址: `http://localhost:8080/dhcp`

#### 6. VPN服务器

- **VPN配置**: 配置VPN服务器参数
- **客户端管理**: 管理VPN客户端连接
- **隧道监控**: 监控VPN隧道状态
- **认证管理**: 配置VPN用户认证

访问地址: `http://localhost:8080/vpn`

#### 7. QoS流量控制

- **带宽管理**: 配置接口带宽限制
- **流量优先级**: 设置不同类型流量的优先级
- **队列管理**: 配置流量队列和调度策略
- **流量统计**: 查看QoS流量统计信息

访问地址: `http://localhost:8080/qos`

#### 8. 系统监控

- **性能监控**: CPU、内存、网络使用率
- **日志查看**: 查看系统日志和事件
- **告警管理**: 配置和查看系统告警
- **统计报表**: 生成各种统计报表

访问地址: `http://localhost:8080/monitor`

### API接口使用

Web界面提供RESTful API，支持程序化管理：

#### 认证方式

```bash
# 使用Basic Authentication
curl -u admin:admin http://localhost:8080/api/routes
```

#### 常用API端点

| 功能 | 方法 | 端点 | 描述 |
|------|------|------|------|
| 路由管理 | GET | `/api/routes` | 获取所有路由 |
| 路由管理 | POST | `/api/routes` | 添加路由 |
| 路由管理 | DELETE | `/api/routes/{id}` | 删除路由 |
| 接口管理 | GET | `/api/interfaces` | 获取所有接口 |
| 接口管理 | PUT | `/api/interfaces/{name}` | 更新接口配置 |
| 防火墙 | GET | `/api/firewall/rules` | 获取防火墙规则 |
| 防火墙 | POST | `/api/firewall/rules` | 添加防火墙规则 |
| DHCP | GET | `/api/dhcp/leases` | 获取DHCP租约 |
| 系统监控 | GET | `/api/monitor/stats` | 获取系统统计 |

### 配置Web服务器

在配置文件中添加Web服务器配置：

```json
{
  "web": {
    "enabled": true,
    "port": 8080,
    "host": "0.0.0.0",
    "auth": {
      "username": "admin",
      "password": "admin"
    },
    "cors": {
      "enabled": true,
      "origins": ["*"]
    },
    "tls": {
      "enabled": false,
      "cert_file": "",
      "key_file": ""
    }
  }
}
```

### 安全配置

#### 1. 修改默认密码

```json
{
  "web": {
    "auth": {
      "username": "admin",
      "password": "your_secure_password"
    }
  }
}
```

#### 2. 启用HTTPS

```json
{
  "web": {
    "tls": {
      "enabled": true,
      "cert_file": "/path/to/cert.pem",
      "key_file": "/path/to/key.pem"
    }
  }
}
```

#### 3. 限制访问来源

```json
{
  "web": {
    "host": "192.168.1.1",  // 只监听特定IP
    "cors": {
      "origins": ["https://admin.example.com"]  // 限制CORS来源
    }
  }
}
```

---

## ⚙️ 配置文件详解

### 基本结构

```json
{
  "interfaces": [...],      // 网络接口配置
  "static_routes": [...],   // 静态路由配置
  "rip": {...},            // RIP 协议配置
  "logging": {...},        // 日志配置
  "monitoring": {...}      // 监控配置
}
```

### 接口配置

```json
{
  "interfaces": [
    {
      "name": "eth0",                    // 接口名称
      "ip_address": "192.168.1.1/24",   // IP 地址和子网掩码
      "gateway": "192.168.1.254",       // 默认网关（可选）
      "mtu": 1500,                      // 最大传输单元
      "enabled": true,                  // 是否启用
      "description": "LAN Interface"    // 接口描述（可选）
    },
    {
      "name": "eth1",
      "ip_address": "10.0.0.1/24",
      "mtu": 1500,
      "enabled": true,
      "description": "WAN Interface"
    }
  ]
}
```

### 静态路由配置

```json
{
  "static_routes": [
    {
      "destination": "192.168.2.0/24",  // 目标网络
      "gateway": "192.168.1.2",         // 下一跳网关
      "interface": "eth0",              // 出接口
      "metric": 1,                      // 度量值
      "description": "To Branch Office" // 路由描述（可选）
    },
    {
      "destination": "0.0.0.0/0",       // 默认路由
      "gateway": "10.0.0.1",
      "interface": "eth1",
      "metric": 10
    }
  ]
}
```

### RIP 协议配置

```json
{
  "rip": {
    "enabled": true,                    // 是否启用 RIP
    "version": 2,                       // RIP 版本（1 或 2）
    "update_interval": 30,              // 更新间隔（秒）
    "timeout": 180,                     // 路由超时时间（秒）
    "garbage_collection": 120,          // 垃圾回收时间（秒）
    "interfaces": ["eth0", "eth1"],     // 启用 RIP 的接口
    "passive_interfaces": [],           // 被动接口（只接收，不发送）
    "authentication": {                 // 认证配置（可选）
      "enabled": false,
      "type": "simple",                 // simple 或 md5
      "password": "secret"
    }
  }
}
```

### 日志配置

```json
{
  "logging": {
    "level": "info",                    // 日志级别：debug, info, warn, error
    "file": "/var/log/router-os.log",   // 日志文件路径
    "max_size": 100,                    // 最大文件大小（MB）
    "max_backups": 5,                   // 保留的备份文件数
    "max_age": 30,                      // 保留天数
    "compress": true                    // 是否压缩旧日志
  }
}
```

### 监控配置

```json
{
  "monitoring": {
    "enabled": true,                    // 是否启用监控
    "interval": 60,                     // 监控间隔（秒）
    "metrics": {
      "system": true,                   // 系统指标
      "interfaces": true,               // 接口指标
      "routing": true                   // 路由指标
    },
    "export": {
      "prometheus": {                   // Prometheus 导出（可选）
        "enabled": false,
        "port": 9090
      }
    }
  }
}
```

---

## 💻 CLI 命令参考

### 基本命令

| 命令 | 描述 | 示例 |
|------|------|------|
| `help` | 显示帮助信息 | `help` |
| `exit` | 退出程序 | `exit` |
| `quit` | 退出程序 | `quit` |
| `clear` | 清屏 | `clear` |

### 路由管理命令

#### 查看路由

```bash
# 显示所有路由
show routes

# 显示详细路由信息
show routes detail

# 显示特定目标的路由
show route 192.168.1.0/24

# 按类型过滤路由
show routes static
show routes dynamic
show routes connected
```

#### 添加路由

```bash
# 添加静态路由
add route <destination> <gateway> <interface> [metric]

# 示例
add route 192.168.2.0/24 192.168.1.2 eth0 1
add route 10.0.0.0/8 192.168.1.1 eth0 5
```

#### 删除路由

```bash
# 删除路由
del route <destination>

# 示例
del route 192.168.2.0/24
del route 10.0.0.0/8
```

#### 修改路由

```bash
# 修改路由度量值
set route <destination> metric <value>

# 示例
set route 192.168.2.0/24 metric 10
```

### 接口管理命令

#### 查看接口

```bash
# 显示所有接口
show interfaces

# 显示详细接口信息
show interfaces detail

# 显示特定接口
show interface eth0

# 显示接口统计信息
show interfaces stats
```

#### 配置接口

```bash
# 启用接口
interface eth0 up

# 禁用接口
interface eth0 down

# 设置接口 IP 地址
interface eth0 ip 192.168.1.1/24

# 设置接口 MTU
interface eth0 mtu 1500
```

#### 接口统计

```bash
# 清除接口统计
clear interface eth0 stats

# 重置所有接口统计
clear interfaces stats
```

### 协议管理命令

#### RIP 协议

```bash
# 启动 RIP 协议
rip start

# 停止 RIP 协议
rip stop

# 显示 RIP 状态
rip show

# 显示 RIP 数据库
rip show database

# 显示 RIP 邻居
rip show neighbors

# 在接口上启用 RIP
rip interface eth0 enable

# 在接口上禁用 RIP
rip interface eth0 disable

# 设置接口为被动模式
rip interface eth0 passive
```

### 系统管理命令

#### 系统信息

```bash
# 显示系统状态
show system

# 显示系统统计
show stats

# 显示版本信息
show version

# 显示运行时间
show uptime
```

#### 配置管理

```bash
# 显示当前配置
show config

# 保存配置
save config

# 重新加载配置
reload config

# 重置配置为默认值
reset config
```

#### 调试命令

```bash
# 设置调试级别
debug level <level>  # debug, info, warn, error

# 启用特定模块调试
debug routing enable
debug rip enable
debug interface enable

# 禁用调试
debug routing disable
debug rip disable
```

---

## 🛣️ 路由管理

### 路由类型说明

1. **直连路由 (Connected)**
   - 自动生成，对应直接连接的网络
   - 优先级最高
   - 不能手动删除

2. **静态路由 (Static)**
   - 手动配置的路由
   - 配置简单，适合小型网络
   - 不会自动适应网络变化

3. **动态路由 (Dynamic)**
   - 通过路由协议学习的路由
   - 自动适应网络变化
   - 适合大型复杂网络

### 路由优先级

路由选择按以下优先级顺序：

1. **最长匹配原则**: 子网掩码最长的路由优先
2. **管理距离**: 数值越小优先级越高
   - 直连路由: 0
   - 静态路由: 1
   - RIP: 120
3. **度量值**: 在同类型路由中，度量值小的优先

### 常用路由配置

#### 默认路由

```bash
# 添加默认路由
add route 0.0.0.0/0 192.168.1.1 eth0 1
```

#### 主机路由

```bash
# 添加到特定主机的路由
add route 192.168.1.100/32 192.168.1.1 eth0 1
```

#### 网络路由

```bash
# 添加到网络的路由
add route 10.0.0.0/8 192.168.1.2 eth0 1
```

---

## 🔌 接口管理

### 接口状态

- **Up**: 接口启用且正常工作
- **Down**: 接口禁用或故障
- **Testing**: 接口处于测试状态

### 接口统计信息

- **TxPackets**: 发送的数据包数量
- **RxPackets**: 接收的数据包数量
- **TxBytes**: 发送的字节数
- **RxBytes**: 接收的字节数
- **Errors**: 错误计数

### 接口配置示例

```bash
# 配置 LAN 接口
interface eth0 ip 192.168.1.1/24
interface eth0 mtu 1500
interface eth0 up

# 配置 WAN 接口
interface eth1 ip 10.0.0.1/24
interface eth1 mtu 1500
interface eth1 up
```

---

## 🔄 协议配置

### RIP 协议配置步骤

1. **启用 RIP 协议**
   ```bash
   rip start
   ```

2. **在接口上启用 RIP**
   ```bash
   rip interface eth0 enable
   rip interface eth1 enable
   ```

3. **配置被动接口**（只接收路由，不发送）
   ```bash
   rip interface eth2 passive
   ```

4. **查看 RIP 状态**
   ```bash
   rip show
   rip show database
   ```

### RIP 故障排除

```bash
# 检查 RIP 是否运行
rip show

# 查看 RIP 数据库
rip show database

# 检查接口 RIP 状态
show interfaces

# 启用 RIP 调试
debug rip enable
```

---

## 🔥 防火墙管理

### 防火墙规则类型

1. **ACCEPT**: 允许数据包通过
2. **DROP**: 静默丢弃数据包
3. **REJECT**: 拒绝数据包并发送响应

### 防火墙配置

#### 配置文件设置

```json
{
  "firewall": {
    "enabled": true,
    "default_policy": "DROP",
    "rules": [
      {
        "id": "allow_ssh",
        "action": "ACCEPT",
        "protocol": "tcp",
        "src_ip": "192.168.1.0/24",
        "dst_port": 22,
        "description": "Allow SSH from LAN"
      },
      {
        "id": "allow_web",
        "action": "ACCEPT",
        "protocol": "tcp",
        "dst_port": 80,
        "description": "Allow HTTP traffic"
      }
    ]
  }
}
```

#### CLI命令

```bash
# 查看防火墙状态
show firewall status

# 查看防火墙规则
show firewall rules

# 添加防火墙规则
firewall add rule allow_http tcp --dst-port 80 --action ACCEPT

# 删除防火墙规则
firewall del rule allow_http

# 启用/禁用防火墙
firewall enable
firewall disable
```

### 常用防火墙规则

```bash
# 允许SSH访问
firewall add rule ssh tcp --src 192.168.1.0/24 --dst-port 22 --action ACCEPT

# 允许Web访问
firewall add rule web tcp --dst-port 80,443 --action ACCEPT

# 阻止特定IP
firewall add rule block_ip any --src 192.168.1.100 --action DROP

# 允许ping
firewall add rule ping icmp --action ACCEPT
```

---

## 🏠 DHCP服务器

### DHCP服务器配置

#### 配置文件设置

```json
{
  "dhcp": {
    "enabled": true,
    "interface": "eth0",
    "pool": {
      "start": "192.168.1.100",
      "end": "192.168.1.200",
      "subnet": "192.168.1.0/24",
      "gateway": "192.168.1.1",
      "dns": ["8.8.8.8", "8.8.4.4"],
      "lease_time": 86400
    },
    "static_leases": [
      {
        "mac": "00:11:22:33:44:55",
        "ip": "192.168.1.10",
        "hostname": "server1"
      }
    ]
  }
}
```

#### CLI命令

```bash
# 查看DHCP状态
show dhcp status

# 查看DHCP租约
show dhcp leases

# 查看DHCP统计
show dhcp stats

# 启用/禁用DHCP服务器
dhcp enable
dhcp disable

# 添加静态租约
dhcp add static 00:11:22:33:44:55 192.168.1.10 server1

# 删除静态租约
dhcp del static 00:11:22:33:44:55
```

### DHCP故障排除

```bash
# 检查DHCP服务状态
show dhcp status

# 查看DHCP日志
show logs dhcp

# 检查IP地址池
show dhcp pool

# 释放特定租约
dhcp release 192.168.1.150
```

---

## 🔐 VPN服务器

### VPN服务器配置

#### 配置文件设置

```json
{
  "vpn": {
    "enabled": true,
    "type": "openvpn",
    "port": 1194,
    "protocol": "udp",
    "network": "10.8.0.0/24",
    "clients": [
      {
        "name": "client1",
        "cert": "/path/to/client1.crt",
        "key": "/path/to/client1.key"
      }
    ],
    "routes": [
      "192.168.1.0/24"
    ]
  }
}
```

#### CLI命令

```bash
# 查看VPN状态
show vpn status

# 查看VPN客户端
show vpn clients

# 查看VPN连接
show vpn connections

# 启用/禁用VPN服务器
vpn enable
vpn disable

# 添加VPN客户端
vpn add client client1 --cert /path/to/cert --key /path/to/key

# 删除VPN客户端
vpn del client client1

# 断开客户端连接
vpn disconnect client1
```

### VPN客户端管理

```bash
# 生成客户端证书
vpn generate cert client2

# 查看客户端配置
vpn show config client1

# 导出客户端配置
vpn export config client1 > client1.ovpn
```

---

## ⚡ QoS流量控制

### QoS配置

#### 配置文件设置

```json
{
  "qos": {
    "enabled": true,
    "interfaces": [
      {
        "name": "eth0",
        "upload_limit": "100Mbps",
        "download_limit": "100Mbps",
        "queues": [
          {
            "name": "high_priority",
            "bandwidth": "50%",
            "priority": 1,
            "rules": [
              {
                "protocol": "tcp",
                "dst_port": 22
              }
            ]
          },
          {
            "name": "normal",
            "bandwidth": "30%",
            "priority": 2
          },
          {
            "name": "low_priority",
            "bandwidth": "20%",
            "priority": 3
          }
        ]
      }
    ]
  }
}
```

#### CLI命令

```bash
# 查看QoS状态
show qos status

# 查看QoS统计
show qos stats

# 查看队列信息
show qos queues

# 启用/禁用QoS
qos enable
qos disable

# 设置接口带宽限制
qos set interface eth0 upload 100Mbps download 100Mbps

# 添加QoS规则
qos add rule high_priority tcp --dst-port 22 --bandwidth 50%

# 删除QoS规则
qos del rule high_priority
```

### 流量优先级设置

```bash
# 高优先级：SSH、DNS
qos add rule ssh tcp --dst-port 22 --priority 1
qos add rule dns udp --dst-port 53 --priority 1

# 中优先级：HTTP、HTTPS
qos add rule web tcp --dst-port 80,443 --priority 2

# 低优先级：P2P、下载
qos add rule p2p tcp --dst-port 6881:6889 --priority 3
```

---

## 📦 数据包捕获

### 数据包捕获配置

#### 配置文件设置

```json
{
  "capture": {
    "enabled": true,
    "interfaces": ["eth0", "eth1"],
    "filters": [
      {
        "name": "web_traffic",
        "filter": "tcp port 80 or tcp port 443",
        "max_packets": 1000
      }
    ],
    "storage": {
      "path": "/var/log/captures",
      "max_size": "100MB",
      "rotation": true
    }
  }
}
```

#### CLI命令

```bash
# 查看捕获状态
show capture status

# 查看捕获统计
show capture stats

# 开始数据包捕获
capture start eth0

# 停止数据包捕获
capture stop eth0

# 查看捕获的数据包
capture show eth0

# 设置捕获过滤器
capture filter eth0 "tcp port 80"

# 导出捕获数据
capture export eth0 /path/to/file.pcap
```

### 数据包分析

```bash
# 按协议统计
capture stats protocol

# 按端口统计
capture stats port

# 按IP地址统计
capture stats ip

# 查看流量趋势
capture stats trend
```

---

## 📊 监控和诊断

### 系统监控

```bash
# 查看系统状态
show system

# 查看系统统计
show stats

# 查看内存使用
show memory

# 查看 CPU 使用
show cpu
```

### 网络诊断

```bash
# 测试连通性
ping 192.168.1.1

# 跟踪路由
traceroute 192.168.1.1

# 查看 ARP 表
show arp

# 查看路由表
show routes
```

### 性能监控

```bash
# 查看接口流量
show interfaces stats

# 查看路由表大小
show routes summary

# 查看协议状态
rip show
```

---

## 📝 常用操作示例

### 场景 1: 配置基本路由器

```bash
# 1. 配置接口
interface eth0 ip 192.168.1.1/24
interface eth0 up
interface eth1 ip 10.0.0.1/24
interface eth1 up

# 2. 添加默认路由
add route 0.0.0.0/0 10.0.0.1 eth1 1

# 3. 添加静态路由
add route 192.168.2.0/24 192.168.1.2 eth0 1

# 4. 查看配置
show interfaces
show routes
```

### 场景 2: 启用 RIP 协议

```bash
# 1. 启动 RIP
rip start

# 2. 在接口上启用 RIP
rip interface eth0 enable
rip interface eth1 enable

# 3. 查看 RIP 状态
rip show
rip show database

# 4. 监控路由学习
show routes dynamic
```

### 场景 3: 网络故障排除

```bash
# 1. 检查接口状态
show interfaces

# 2. 检查路由表
show routes

# 3. 测试连通性
ping 192.168.1.1

# 4. 启用调试
debug routing enable
debug rip enable

# 5. 查看日志
show logs
```

### 场景 4: 性能优化

```bash
# 1. 查看接口统计
show interfaces stats

# 2. 查看路由表大小
show routes summary

# 3. 优化路由表
# 删除不必要的路由
del route 192.168.100.0/24

# 4. 调整 RIP 参数
# 在配置文件中修改 update_interval
```

---

## 📋 配置模板

### 小型办公室路由器

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip_address": "192.168.1.1/24",
      "mtu": 1500,
      "enabled": true,
      "description": "LAN Interface"
    },
    {
      "name": "eth1",
      "ip_address": "10.0.0.2/24",
      "mtu": 1500,
      "enabled": true,
      "description": "WAN Interface"
    }
  ],
  "static_routes": [
    {
      "destination": "0.0.0.0/0",
      "gateway": "10.0.0.1",
      "interface": "eth1",
      "metric": 1,
      "description": "Default Route"
    }
  ],
  "rip": {
    "enabled": false
  }
}
```

### 企业分支路由器

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip_address": "192.168.10.1/24",
      "mtu": 1500,
      "enabled": true,
      "description": "Branch LAN"
    },
    {
      "name": "eth1",
      "ip_address": "172.16.1.2/30",
      "mtu": 1500,
      "enabled": true,
      "description": "WAN to HQ"
    }
  ],
  "static_routes": [
    {
      "destination": "192.168.0.0/16",
      "gateway": "172.16.1.1",
      "interface": "eth1",
      "metric": 1,
      "description": "HQ Networks"
    }
  ],
  "rip": {
    "enabled": true,
    "update_interval": 30,
    "interfaces": ["eth1"]
  }
}
```

### 实验室测试环境

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip_address": "10.1.1.1/24",
      "mtu": 1500,
      "enabled": true
    },
    {
      "name": "eth1",
      "ip_address": "10.1.2.1/24",
      "mtu": 1500,
      "enabled": true
    },
    {
      "name": "eth2",
      "ip_address": "10.1.3.1/24",
      "mtu": 1500,
      "enabled": true
    }
  ],
  "rip": {
    "enabled": true,
    "update_interval": 10,
    "interfaces": ["eth0", "eth1", "eth2"]
  },
  "logging": {
    "level": "debug"
  }
}
```

---

## ⚡ 命令速查表

### 路由命令

| 操作 | 命令 |
|------|------|
| 查看所有路由 | `show routes` |
| 查看路由详情 | `show routes detail` |
| 添加静态路由 | `add route <dest> <gw> <if> [metric]` |
| 删除路由 | `del route <dest>` |
| 修改路由度量 | `set route <dest> metric <value>` |

### 接口命令

| 操作 | 命令 |
|------|------|
| 查看所有接口 | `show interfaces` |
| 查看接口详情 | `show interfaces detail` |
| 启用接口 | `interface <name> up` |
| 禁用接口 | `interface <name> down` |
| 设置 IP 地址 | `interface <name> ip <ip/mask>` |
| 查看接口统计 | `show interfaces stats` |

### RIP 命令

| 操作 | 命令 |
|------|------|
| 启动 RIP | `rip start` |
| 停止 RIP | `rip stop` |
| 查看 RIP 状态 | `rip show` |
| 查看 RIP 数据库 | `rip show database` |
| 接口启用 RIP | `rip interface <name> enable` |
| 接口禁用 RIP | `rip interface <name> disable` |

### 系统命令

| 操作 | 命令 |
|------|------|
| 查看系统状态 | `show system` |
| 查看统计信息 | `show stats` |
| 保存配置 | `save config` |
| 重载配置 | `reload config` |
| 显示帮助 | `help` |
| 退出程序 | `exit` |

### 调试命令

| 操作 | 命令 |
|------|------|
| 设置日志级别 | `debug level <level>` |
| 启用路由调试 | `debug routing enable` |
| 启用 RIP 调试 | `debug rip enable` |
| 禁用调试 | `debug <module> disable` |

---

## 📞 技术支持

如果在使用过程中遇到问题，请：

1. 查看日志文件获取错误信息
2. 使用调试命令获取详细信息
3. 参考故障排除章节
4. 提交 GitHub Issue

---

**📖 本手册涵盖了 Router OS 的主要使用方法，更多高级功能请参考 [学习指南](LEARNING_GUIDE.md) 和 [架构文档](ARCHITECTURE.md)。**