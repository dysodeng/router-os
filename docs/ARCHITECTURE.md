# Router OS 架构设计文档

## 概述

Router OS 是一个使用 Go 语言实现的简化路由器操作系统，旨在演示现代路由器的核心功能和架构设计。

## 系统架构

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Router OS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Web Interface          │  CLI Interface          │  Configuration Manager │
│  - Web 管理界面          │  - 命令行交互            │  - JSON 配置文件        │
│  - RESTful API          │  - 实时控制              │  - 动态配置更新         │
│  - 认证系统              │  - 交互式操作            │  - 配置验证             │
├─────────────────────────┼─────────────────────────┼─────────────────────────┤
│  Database System        │  Logging System         │  Monitoring System      │
│  - SQLite 数据库         │  - 分级日志              │  - 系统状态监控         │
│  - 数据持久化            │  - 文件/控制台输出        │  - 性能指标收集         │
│  - 配置存储              │  - 日志轮转              │  - 实时监控             │
├─────────────────────────────────────────────────────────────────────────────┤
│                              Router Core                                   │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐   │
│  │ Routing     │ Interface   │ Packet      │ ARP Table   │ Packet      │   │
│  │ Table       │ Manager     │ Processor   │ Manager     │ Capture     │   │
│  │ - 路由表管理 │ - 接口发现   │ - 数据包处理 │ - ARP 缓存   │ - 数据包捕获 │   │
│  │ - 最长前缀   │ - 状态监控   │ - 转发决策   │ - 地址解析   │ - 流量分析   │   │
│  │ - 路由老化   │ - 统计信息   │ - 本地交付   │ - 邻居发现   │ - 性能监控   │   │
│  └─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Network Services                                 │
│  ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐   │
│  │ Firewall    │ DHCP Server │ VPN Server  │ QoS Manager │ NAT Manager │   │
│  │ - 防火墙规则 │ - IP 地址分配│ - VPN 连接   │ - 流量控制   │ - 地址转换   │   │
│  │ - 访问控制   │ - 租约管理   │ - 隧道管理   │ - 带宽限制   │ - 端口映射   │   │
│  │ - 安全策略   │ - DNS 服务   │ - 客户端管理 │ - 优先级队列 │ - 连接跟踪   │   │
│  └─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Protocol Stack                                   │
│  ┌─────────────┬─────────────────────────────────────────────────────────┐ │
│  │ Static      │                RIP Protocol                            │ │
│  │ Routes      │  - 距离向量算法                                          │ │
│  │ - 静态路由   │  - 定期更新                                             │ │
│  │ - 手动管理   │  - 邻居发现                                             │ │
│  │             │  - 路由学习和传播                                        │ │
│  └─────────────┴─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 核心组件

### 1. Router Core (`internal/router/`)

路由器的核心组件，负责协调各个子系统的工作。

**主要功能：**
- 系统初始化和启动
- 组件生命周期管理
- 子系统间的协调

**关键接口：**
```go
type Router struct {
    routingTable    *routing.Table
    interfaceManager *interfaces.Manager
    packetProcessor *packet.Processor
    // ...
}

func (r *Router) Start() error
func (r *Router) Stop() error
```

### 2. Routing Table (`internal/routing/`)

实现路由表的核心数据结构和算法。

**主要功能：**
- 路由条目的增删改查
- 最长前缀匹配算法
- 路由度量值比较
- 动态路由老化机制

**数据结构：**
```go
type Route struct {
    Destination *net.IPNet    // 目标网络
    Gateway     net.IP        // 网关
    Interface   string        // 出接口
    Metric      int           // 路由度量值
    Type        RouteType     // 路由类型
    Age         time.Time     // 路由创建时间
    TTL         time.Duration // 生存时间
}
```

**算法特点：**
- 使用切片存储路由条目
- 按前缀长度和度量值排序
- 支持并发安全访问（读写锁）

### 3. Interface Manager (`internal/interfaces/`)

网络接口管理组件，负责发现和管理系统网络接口。

**主要功能：**
- 自动发现系统网络接口
- 接口状态监控
- 接口统计信息收集
- 接口配置管理

**接口状态：**
- `InterfaceStatusDown` - 接口关闭
- `InterfaceStatusUp` - 接口启用
- `InterfaceStatusTesting` - 接口测试中

### 4. Packet Processor (`internal/packet/`)

数据包处理引擎，实现数据包的接收、处理和转发。

**主要功能：**
- 数据包类型识别
- 转发决策制定
- 本地数据包交付
- 数据包统计

**数据包类型：**
- IPv4 数据包
- IPv6 数据包
- ARP 数据包
- 其他协议数据包

### 5. Protocol Stack (`internal/protocols/`)

路由协议实现，目前支持静态路由和 RIP 协议。

#### 5.1 Static Routes (`static.go`)

静态路由管理器，提供手动路由配置功能。

**特点：**
- 永久有效（不会老化）
- 手动配置和删除
- 高优先级（低度量值）

#### 5.2 RIP Protocol (`rip.go`)

实现 RIP（Routing Information Protocol）距离向量路由协议。

**协议特性：**
- 距离向量算法
- 最大跳数限制（15跳）
- 定期更新机制
- 水平分割防环
- 路由老化和垃圾回收

**RIP 数据包格式：**
```go
type RIPPacket struct {
    Command byte        // 命令类型
    Version byte        // 版本号
    Entries []RIPEntry  // 路由条目
}

type RIPEntry struct {
    Network *net.IPNet  // 目标网络
    Metric  int         // 跳数
}
```

### 6. Configuration Manager (`internal/config/`)

配置管理系统，支持 JSON 格式的配置文件。

**配置项：**
- 网络接口配置
- 静态路由配置
- RIP 协议参数
- 系统参数

**配置文件结构：**
```json
{
  "interfaces": [...],
  "static_routes": [...],
  "rip": {
    "enabled": true,
    "update_interval": 30,
    "timeout": 180,
    "garbage_collection": 120
  }
}
```

### 7. CLI Interface (`internal/cli/`)

命令行接口，提供实时的系统管理和监控功能。

**支持的命令：**
- `show routes` - 显示路由表
- `show interfaces` - 显示接口状态
- `show stats` - 显示系统统计
- `add route` - 添加静态路由
- `del route` - 删除路由
- `rip start/stop` - RIP 协议控制

### 8. Web Management Interface (`internal/web/`)

Web 管理界面，提供图形化的路由器管理功能。

**主要功能：**
- 仪表板显示系统状态
- 路由表管理界面
- 接口配置和监控
- 防火墙规则管理
- DHCP 服务器配置
- VPN 服务器管理
- QoS 流量控制
- 系统监控和统计

**技术特点：**
- RESTful API 设计
- 基本认证（Basic Authentication）
- 响应式 Web 界面
- 实时数据更新
- CORS 支持

**组件结构：**
```go
// Web 服务器
type Server struct {
    config *Config
    router *router.Router
    server *http.Server
}

// 处理器
- AuthHandler     // 认证处理
- DashboardHandler // 仪表板
- RoutesHandler   // 路由管理
- InterfacesHandler // 接口管理
- FirewallHandler // 防火墙管理
- DHCPHandler     // DHCP 管理
- VPNHandler      // VPN 管理
- QoSHandler      // QoS 管理
- MonitorHandler  // 监控数据
```

### 9. Database System (`internal/database/`)

数据库系统，提供数据持久化功能。

**主要功能：**
- SQLite 数据库支持
- 配置数据存储
- 系统状态持久化
- 历史数据记录
- 数据库迁移

**数据表结构：**
- 配置表（configurations）
- 路由表（routes）
- 接口表（interfaces）
- 日志表（logs）
- 统计表（statistics）

### 10. ARP Table Manager (`internal/module/arp/`)

ARP 表管理组件，处理地址解析协议。

**主要功能：**
- ARP 缓存管理
- 地址解析请求
- 邻居发现
- ARP 表老化
- 接口智能选择

**ARP 条目结构：**
```go
type ARPEntry struct {
    IP        net.IP    // IP 地址
    MAC       net.HardwareAddr // MAC 地址
    Interface string    // 接口名称
    State     ARPState  // 条目状态
    LastSeen  time.Time // 最后发现时间
}
```

### 11. Packet Capture (`internal/module/capture/`)

数据包捕获和分析组件。

**主要功能：**
- 网络接口监听
- 数据包捕获
- 协议解析
- 流量统计
- 性能分析

**统计信息：**
- 接收数据包数量
- 发送数据包数量
- 处理数据包数量
- 转发数据包数量
- 丢弃数据包数量

### 12. Network Services

#### 12.1 Firewall (`internal/module/firewall/`)

防火墙模块，提供网络安全功能。

**主要功能：**
- 防火墙规则管理
- 访问控制列表
- 数据包过滤
- 安全策略执行

**规则类型：**
- ACCEPT - 允许通过
- DROP - 丢弃数据包
- REJECT - 拒绝并回复

#### 12.2 DHCP Server (`internal/module/dhcp/`)

DHCP 服务器模块，提供动态 IP 地址分配。

**主要功能：**
- IP 地址池管理
- 租约管理
- DNS 服务器配置
- 客户端管理

**DHCP 租约：**
```go
type Lease struct {
    IP       net.IP    // 分配的 IP 地址
    MAC      net.HardwareAddr // 客户端 MAC
    Hostname string    // 主机名
    LeaseTime time.Time // 租约开始时间
    Expires  time.Time // 租约过期时间
}
```

#### 12.3 VPN Server (`internal/module/vpn/`)

VPN 服务器模块，提供虚拟专用网络功能。

**主要功能：**
- VPN 隧道管理
- 客户端认证
- 加密通信
- 路由配置

#### 12.4 QoS Manager (`internal/module/qos/`)

服务质量管理模块，提供流量控制功能。

**主要功能：**
- 带宽限制
- 流量优先级
- 队列管理
- 流量整形

#### 12.5 NAT Manager (`internal/module/nat/`)

网络地址转换模块。

**主要功能：**
- 地址转换
- 端口映射
- 连接跟踪
- 会话管理

### 13. Logging System (`internal/logging/`)

分级日志系统，支持多种输出目标。

**日志级别：**
- DEBUG - 调试信息
- INFO - 一般信息
- WARN - 警告信息
- ERROR - 错误信息

**输出目标：**
- 控制台输出
- 文件输出
- 可配置的日志轮转

### 14. Monitoring System (`internal/monitoring/`)

系统监控组件，收集和报告系统运行状态。

**监控指标：**
- 系统运行时间
- 内存使用情况
- Goroutine 数量
- 路由表大小
- 接口统计信息
- 数据包处理统计

## 数据流

### 路由更新流程

1. **协议接收** - 协议栈接收路由更新
2. **验证处理** - 验证路由信息的有效性
3. **路由计算** - 计算最优路径
4. **表更新** - 更新路由表
5. **数据库同步** - 将路由信息同步到数据库
6. **通知发送** - 向其他协议发送更新通知
7. **Web界面更新** - 通知Web界面更新显示

### 数据包处理流程

1. **接收** - 从网络接口接收数据包
2. **捕获分析** - 数据包捕获模块记录统计信息
3. **防火墙检查** - 防火墙模块检查访问规则
4. **NAT处理** - NAT模块处理地址转换
5. **解析** - 解析数据包头部信息
6. **路由查找** - 在路由表中查找目标路由
7. **QoS处理** - QoS模块应用流量控制策略
8. **转发决策** - 决定转发或丢弃
9. **发送** - 通过相应接口发送数据包
10. **统计更新** - 更新接口和系统统计信息

### Web管理数据流

1. **用户请求** - 用户通过浏览器发送HTTP请求
2. **认证验证** - Web服务器验证用户身份
3. **API处理** - 相应的处理器处理API请求
4. **数据查询** - 从数据库或内存中查询数据
5. **业务逻辑** - 执行相应的业务逻辑操作
6. **数据返回** - 将结果以JSON格式返回给客户端
7. **界面更新** - 前端界面根据返回数据更新显示

### 配置管理数据流

1. **配置读取** - 从配置文件或数据库读取配置
2. **配置验证** - 验证配置参数的有效性
3. **配置应用** - 将配置应用到相应模块
4. **配置持久化** - 将配置保存到数据库
5. **模块通知** - 通知相关模块配置已更新
6. **Web界面同步** - 同步配置到Web管理界面

### 监控数据流

1. **数据收集** - 各组件收集运行数据
2. **数据聚合** - 监控系统聚合统计信息
3. **数据库存储** - 将监控数据存储到数据库
4. **阈值检查** - 检查是否超过预设阈值
5. **告警生成** - 生成告警信息
6. **Web推送** - 将实时数据推送到Web界面
7. **历史分析** - 提供历史数据分析功能

## 并发模型

系统采用 Go 语言的 goroutine 并发模型：

1. **主 goroutine**: 系统初始化和信号处理
2. **RIP 协议 goroutine**: 定期更新和邻居超时检查
3. **监控 goroutine**: 定期收集系统统计信息
4. **CLI goroutine**: 处理用户命令输入
5. **数据包处理 goroutine**: 处理入站数据包

## 同步机制

- **读写锁**: 路由表访问保护
- **互斥锁**: 接口管理器状态保护
- **通道**: 组件间异步通信
- **上下文**: 优雅关闭控制

## 扩展性设计

### 1. 新协议支持

添加新的路由协议只需：
1. 在 `internal/protocols/` 下实现协议逻辑
2. 在路由器核心中注册协议
3. 更新配置管理器支持新协议参数

### 2. 新功能模块

系统采用模块化设计，新功能可以作为独立模块添加：
1. 实现模块接口
2. 在路由器核心中集成
3. 更新 CLI 支持新命令

### 3. 性能优化

- 路由表可以替换为更高效的数据结构（如 Trie 树）
- 数据包处理可以使用零拷贝技术
- 添加缓存机制减少路由查找开销

## 测试策略

### 1. 单元测试

每个组件都有对应的单元测试：
- 路由表操作测试
- 协议逻辑测试
- 配置解析测试

### 2. 集成测试

- 组件间交互测试
- 端到端功能测试
- 性能基准测试

### 3. 示例程序

提供完整的功能演示程序，展示系统各项功能。

## 部署和运维

### 1. 构建

使用 Makefile 简化构建过程：
```bash
make build    # 构建可执行文件
make test     # 运行测试
make demo     # 运行演示
```

### 2. 配置

通过 JSON 配置文件进行系统配置，支持运行时重新加载。

### 3. 监控

内置监控系统提供实时的系统状态信息，便于运维管理。

## 安全考虑

1. **输入验证**: 所有外部输入都进行严格验证
2. **权限控制**: CLI 命令需要适当的权限检查
3. **资源限制**: 防止资源耗尽攻击
4. **日志安全**: 避免敏感信息泄露

## 性能特性

- **内存效率**: 使用高效的数据结构
- **并发处理**: 支持多核并行处理
- **低延迟**: 优化的路由查找算法
- **高吞吐**: 批量处理机制

## 限制和已知问题

1. 这是一个教学和演示用的简化实现
2. 不支持硬件数据平面加速
3. RIP 协议实现不包括所有 RFC 特性
4. 缺少高级安全功能
5. 不适合生产环境使用

## 未来发展方向

1. 支持更多路由协议（OSPF、BGP）
2. 添加 QoS 功能
3. 实现 MPLS 支持
4. 添加 Web 管理界面
5. 支持 SDN 控制器集成