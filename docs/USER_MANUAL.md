# Router OS 用户使用手册

## 📋 目录

1. [安装和启动](#安装和启动)
2. [配置文件详解](#配置文件详解)
3. [CLI 命令参考](#cli-命令参考)
4. [路由管理](#路由管理)
5. [接口管理](#接口管理)
6. [协议配置](#协议配置)
7. [监控和诊断](#监控和诊断)
8. [常用操作示例](#常用操作示例)
9. [配置模板](#配置模板)
10. [命令速查表](#命令速查表)

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