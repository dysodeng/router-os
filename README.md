# Router OS

一个用Go语言实现的高性能路由器操作系统，提供完整的网络路由、转发和管理功能。

## 特性

### 核心功能
- **高性能路由表**: 基于Trie树的快速路由查找，支持IPv4/IPv6
- **多协议支持**: RIP, OSPF, BGP, IS-IS等动态路由协议实现
- **数据包转发**: 高效的数据包处理和转发引擎
- **网络接口管理**: 自动发现和管理网络接口，支持状态监控
- **ARP表管理**: 自动ARP学习和老化机制

### 高级功能
- **负载均衡**: 支持多种负载均衡算法
- **故障转移**: 自动路径故障检测和切换
- **防火墙**: 基于规则的数据包过滤和安全策略
- **QoS流量控制**: 带宽限制和流量整形
- **DHCP服务器**: 动态IP地址分配和租约管理
- **VPN支持**: VPN服务器功能
- **NAT转换**: 网络地址转换和端口映射

### 管理功能
- **Web管理界面**: 现代化的Web UI管理，支持认证和实时监控
- **CLI管理**: 功能丰富的命令行界面，支持交互式操作
- **配置管理**: 灵活的JSON配置文件支持
- **性能监控**: 实时性能指标收集、数据包捕获和流量分析
- **数据包捕获**: 网络接口数据包监控和分析

## 快速开始

### 系统要求

- Go 1.19+
- Linux系统（推荐Ubuntu 20.04+）
- 管理员权限（用于网络接口操作）

### 编译

```bash
# 克隆项目
git clone <repository-url>
cd router-os

# 编译主程序
go build -o router-os ./cmd/router

# 或使用Makefile
make build
```

### 运行

```bash
# 使用默认配置运行
sudo ./router-os

# 指定端口和配置
sudo ./router-os -port 8080 -host 0.0.0.0

# 查看帮助
./router-os -help
```

### Web管理界面

启动后访问 http://localhost:8080 进入Web管理界面

- 默认用户名: `admin`
- 默认密码: `admin123`

### 配置

编辑 `config.json` 文件来配置路由器：

```json
{
  "web": {
    "port": 8080,
    "host": "0.0.0.0",
    "username": "admin",
    "password": "admin123"
  },
  "dhcp": {
    "enabled": true,
    "interface": "eth0",
    "start_ip": "192.168.1.100",
    "end_ip": "192.168.1.200",
    "gateway": "192.168.1.1",
    "dns_servers": ["8.8.8.8", "8.8.4.4"],
    "lease_time": 86400
  },
  "vpn": {
    "enabled": false,
    "port": 1194,
    "protocol": "udp",
    "subnet": "10.8.0.0/24"
  },
  "firewall": {
    "enabled": true,
    "default_policy": "DROP"
  },
  "qos": {
    "enabled": false,
    "default_bandwidth": 100
  },
  "logging": {
    "level": "info",
    "file": "/var/log/router-os.log"
  },
  "database": {
    "driver": "sqlite3",
    "dsn": "./router.db",
    "max_idle_conns": 10,
    "max_open_conns": 100,
    "conn_max_lifetime": 3600,
    "conn_max_idle_time": 1800
  }
}
```

## 架构

Router OS采用模块化设计，主要组件包括：

### 核心模块
- **路由表模块** (`internal/module/routing`): 管理路由信息和查找，支持IPv4/IPv6
- **转发引擎** (`internal/module/forwarding`): 处理数据包转发逻辑
- **接口管理** (`internal/module/interfaces`): 网络接口的配置和监控
- **ARP管理** (`internal/module/arp`): ARP表维护和解析
- **数据包处理** (`internal/module/packet`): 数据包解析和处理

### 网络服务
- **DHCP服务器** (`internal/module/dhcp`): 动态IP地址分配和租约管理
- **防火墙** (`internal/module/firewall`): 数据包过滤和安全策略
- **QoS引擎** (`internal/module/qos`): 流量控制和带宽管理
- **VPN服务** (`internal/module/vpn`): 虚拟专用网络服务
- **NAT模块** (`internal/module/nat`): 网络地址转换

### 监控和分析
- **数据包捕获** (`internal/module/capture`): 网络数据包捕获和分析
- **性能监控** (`internal/module/monitoring`): 系统性能指标收集
- **流量分析** (`internal/module/capture`): 实时流量统计和异常检测

### 管理界面
- **Web界面** (`internal/web`): HTTP管理接口，包含完整的前端界面
- **CLI系统** (`internal/module/cli`): 命令行管理界面，支持交互式操作
- **认证系统** (`internal/web/auth`): 用户认证和权限管理

### 协议支持
- **静态路由** (`internal/module/protocols/static`)
- **RIP协议** (`internal/module/protocols/rip`): RIPv2协议实现
- **OSPF协议** (`internal/module/protocols/ospf`): OSPF邻居发现和维护
- **BGP协议** (`internal/module/protocols/bgp`): BGP-4协议实现
- **IS-IS协议** (`internal/module/protocols/isis`): IS-IS协议支持

### 数据存储
- **数据库模块** (`internal/database`): SQLite数据库支持，用于持久化配置和状态
- **配置管理** (`internal/config`): JSON配置文件管理

## 使用示例

### 基本路由配置

```bash
# 添加静态路由
curl -X POST http://localhost:8080/api/routes/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"destination": "192.168.2.0/24", "gateway": "192.168.1.1", "interface": "eth0"}'

# 查看路由表
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/routes
```

### 防火墙规则

```bash
# 查看防火墙规则
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/firewall/rules

# 添加防火墙规则
curl -X POST http://localhost:8080/api/firewall/rules/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"action": "ACCEPT", "protocol": "tcp", "source": "192.168.1.0/24", "destination": "any", "port": 80}'
```

### 接口管理

```bash
# 查看网络接口
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/interfaces

# 查看接口统计信息
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/interfaces/stats
```

### DHCP管理

```bash
# 查看DHCP租约
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/dhcp/leases

# 查看DHCP配置
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/dhcp/config
```

### 系统监控

```bash
# 查看系统状态
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/monitor/system

# 查看网络统计
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/monitor/network

# 查看防火墙统计
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/monitor/firewall
```

### 用户认证

```bash
# 登录获取token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# 验证token
curl -X POST http://localhost:8080/api/auth/verify \
  -H "Authorization: Bearer <token>"
```

## 部署

### 系统服务

```bash
# 复制服务文件
sudo cp deploy/router-os.service /etc/systemd/system/

# 启用服务
sudo systemctl enable router-os
sudo systemctl start router-os

# 查看状态
sudo systemctl status router-os
```

### Docker部署

```bash
# 构建镜像
docker build -t router-os .

# 运行容器
docker run -d --name router-os \
  --privileged \
  --network host \
  -v /etc/router-os:/etc/router-os \
  router-os
```

## 开发

### 项目结构

```
router-os/
├── cmd/router/          # 主程序入口
├── internal/            # 内部模块
│   ├── config/         # 配置管理
│   ├── database/       # 数据库模块
│   ├── module/         # 核心功能模块
│   │   ├── arp/        # ARP表管理
│   │   ├── capture/    # 数据包捕获
│   │   ├── cli/        # CLI命令行界面
│   │   ├── dhcp/       # DHCP服务器
│   │   ├── firewall/   # 防火墙
│   │   ├── forwarding/ # 数据包转发
│   │   ├── interfaces/ # 接口管理
│   │   ├── monitoring/ # 性能监控
│   │   ├── nat/        # NAT转换
│   │   ├── packet/     # 数据包处理
│   │   ├── protocols/  # 路由协议
│   │   │   ├── bgp/    # BGP协议
│   │   │   ├── isis/   # IS-IS协议
│   │   │   ├── ospf/   # OSPF协议
│   │   │   ├── rip/    # RIP协议
│   │   │   └── static/ # 静态路由
│   │   ├── qos/        # QoS流量控制
│   │   ├── routing/    # 路由表
│   │   └── vpn/        # VPN服务
│   └── web/            # Web管理界面
│       ├── auth/       # 认证中间件
│       ├── handlers/   # HTTP处理器
│       └── templates/  # 模板引擎
├── templates/          # HTML模板文件
│   ├── static/         # 静态资源
│   ├── dashboard/      # 仪表板页面
│   ├── interfaces/     # 接口管理页面
│   ├── routes/         # 路由管理页面
│   ├── firewall/       # 防火墙页面
│   ├── dhcp/          # DHCP页面
│   ├── vpn/           # VPN页面
│   ├── qos/           # QoS页面
│   └── monitor/       # 监控页面
├── docs/              # 文档
├── examples/          # 示例代码
└── deploy/           # 部署脚本
```

### 测试

```bash
# 运行所有测试
go test ./...

# 运行特定模块测试
go test ./internal/routing

# 性能测试
go test -bench=. ./internal/routing
```

## 文档

- [架构文档](docs/ARCHITECTURE.md) - 系统架构和设计原理
- [API参考](docs/API_REFERENCE.md) - REST API接口文档
- [用户手册](docs/USER_MANUAL.md) - 详细使用说明
- [学习指南](docs/LEARNING_GUIDE.md) - 路由器基础知识

## 贡献

欢迎提交Issue和Pull Request来改进项目。

## 许可证

MIT License