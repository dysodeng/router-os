# Router OS

一个用Go语言实现的高性能路由器操作系统，提供完整的网络路由、转发和管理功能。

## 特性

### 核心功能
- **高性能路由表**: 基于Trie树的快速路由查找
- **多协议支持**: RIP, OSPF, BGP, IS-IS等动态路由协议
- **数据包转发**: 高效的数据包处理和转发引擎
- **网络接口管理**: 自动发现和管理网络接口
- **ARP表管理**: 自动ARP学习和老化机制

### 高级功能
- **负载均衡**: 支持多种负载均衡算法
- **故障转移**: 自动路径故障检测和切换
- **防火墙**: 基于规则的数据包过滤
- **QoS流量控制**: 带宽限制和流量整形
- **DHCP服务器**: 动态IP地址分配
- **VPN支持**: OpenVPN、WireGuard、IPSec协议

### 管理功能
- **Web管理界面**: 现代化的Web UI管理
- **CLI管理**: 功能丰富的命令行界面
- **配置管理**: 灵活的配置文件支持
- **性能监控**: 实时性能指标收集和分析

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
    "start_ip": "192.168.1.100",
    "end_ip": "192.168.1.200",
    "gateway": "192.168.1.1"
  },
  "firewall": {
    "enabled": true,
    "default_policy": "DROP"
  }
}
```

## 架构

Router OS采用模块化设计，主要组件包括：

### 核心模块
- **路由表模块** (`internal/routing`): 管理路由信息和查找
- **转发引擎** (`internal/forwarding`): 处理数据包转发逻辑
- **接口管理** (`internal/interfaces`): 网络接口的配置和监控
- **ARP管理** (`internal/arp`): ARP表维护和解析

### 网络服务
- **DHCP服务器** (`internal/dhcp`): 动态IP地址分配
- **防火墙** (`internal/firewall`): 数据包过滤和安全
- **QoS引擎** (`internal/qos`): 流量控制和带宽管理
- **VPN服务** (`internal/vpn`): 虚拟专用网络

### 管理界面
- **Web界面** (`internal/web`): HTTP管理接口
- **CLI系统** (`internal/cli`): 命令行管理界面

### 协议支持
- **静态路由** (`internal/protocols/static`)
- **RIP协议** (`internal/protocols/rip`)
- **OSPF协议** (`internal/protocols/ospf`)
- **BGP协议** (`internal/protocols/bgp`)

## 使用示例

### 基本路由配置

```bash
# 添加静态路由
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -d '{"destination": "192.168.2.0/24", "gateway": "192.168.1.1", "interface": "eth0"}'

# 查看路由表
curl http://localhost:8080/api/routes
```

### 防火墙规则

```bash
# 添加防火墙规则
curl -X POST http://localhost:8080/api/firewall \
  -H "Content-Type: application/json" \
  -d '{"action": "ACCEPT", "source": "192.168.1.0/24", "destination": "any", "port": 80}'
```

### 接口管理

```bash
# 查看网络接口
curl http://localhost:8080/api/interfaces

# 配置接口IP
curl -X POST http://localhost:8080/api/interfaces \
  -H "Content-Type: application/json" \
  -d '{"name": "eth0", "ip": "192.168.1.1", "mask": "255.255.255.0"}'
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
│   ├── arp/            # ARP表管理
│   ├── dhcp/           # DHCP服务器
│   ├── firewall/       # 防火墙
│   ├── forwarding/     # 数据包转发
│   ├── interfaces/     # 接口管理
│   ├── protocols/      # 路由协议
│   ├── qos/           # QoS流量控制
│   ├── routing/       # 路由表
│   ├── vpn/           # VPN服务
│   └── web/           # Web管理界面
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