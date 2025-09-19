# Router OS 完整学习指南

## 📚 目录

1. [项目概述](#项目概述)
2. [环境准备](#环境准备)
3. [快速入门](#快速入门)
4. [核心概念详解](#核心概念详解)
5. [实践教程](#实践教程)
6. [高级功能](#高级功能)
7. [故障排除](#故障排除)
8. [最佳实践](#最佳实践)
9. [扩展开发](#扩展开发)
10. [参考资料](#参考资料)

---

## 🎯 项目概述

### 什么是 Router OS？

Router OS 是一个使用 Go 语言实现的教学型路由器操作系统，旨在帮助学习者理解网络路由的基本原理和实现机制。

### 🌟 核心特性

- **📊 路由表管理**: 完整的路由表操作和管理功能
- **🔄 多协议支持**: 静态路由和 RIP 动态路由协议
- **🌐 接口管理**: 自动发现和管理网络接口
- **📦 数据包处理**: 基本的数据包转发逻辑
- **⚙️ 配置管理**: 灵活的 JSON 配置系统
- **💻 CLI 界面**: 直观的命令行管理工具
- **📝 日志系统**: 分级日志记录和调试
- **📈 系统监控**: 实时性能和状态监控

### 🎓 学习目标

通过本项目，你将学会：
- 理解路由器的工作原理
- 掌握路由表的管理和操作
- 了解静态路由和动态路由的区别
- 学习网络接口的管理方法
- 掌握数据包的转发过程
- 理解路由协议的实现原理

---

## 🛠️ 环境准备

### 系统要求

- **操作系统**: Linux, macOS, Windows
- **Go 版本**: 1.19 或更高版本
- **内存**: 至少 512MB
- **磁盘空间**: 100MB

### 安装 Go 环境

#### macOS
```bash
# 使用 Homebrew 安装
brew install go

# 或下载官方安装包
# https://golang.org/dl/
```

#### Linux (Ubuntu/Debian)
```bash
# 使用包管理器安装
sudo apt update
sudo apt install golang-go

# 或使用官方二进制包
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

#### Windows
1. 下载官方安装包：https://golang.org/dl/
2. 运行安装程序
3. 配置环境变量

### 验证安装

```bash
go version
# 应该显示类似：go version go1.21.0 darwin/amd64
```

---

## 🚀 快速入门

### 1. 获取项目

```bash
# 克隆项目（如果是从 Git 仓库）
git clone <repository-url>
cd router-os

# 或者直接使用现有项目目录
cd /path/to/router-os
```

### 2. 初始化依赖

```bash
# 初始化 Go 模块
go mod init router-os
go mod tidy
```

### 3. 构建项目

```bash
# 构建可执行文件
go build -o router-os main.go

# 或者直接运行
go run main.go
```

### 4. 运行演示程序

```bash
# 运行基础演示
go run examples/basic_demo.go
```

### 5. 第一次体验

运行演示程序后，你将看到：

```
=== Router OS 基础功能演示 ===

=== 路由算法概念演示 ===
[演示各种路由算法的工作原理]

=== 实际路由器功能测试 ===

1. 路由表管理测试
当前路由表:
目标网络: 192.168.1.0/24, 网关: 192.168.1.1, 接口: eth0, 度量值: 1

2. 数据包处理测试
处理数据包: 192.168.1.100 -> 10.0.0.100

3. 接口管理测试
发现的网络接口:
- en0: 状态=Up, IP=192.168.1.100
```

---

## 📖 核心概念详解

### 🗺️ 路由表 (Routing Table)

路由表是路由器的"地图"，记录了如何到达不同的网络目标。

#### 路由表结构

```go
type Route struct {
    Destination net.IPNet    // 目标网络
    Gateway     net.IP       // 下一跳网关
    Interface   string       // 出接口
    Metric      int          // 度量值（成本）
    Type        RouteType    // 路由类型
    Age         time.Time    // 路由年龄
}
```

#### 路由类型

1. **直连路由 (Connected)**
   - 直接连接到路由器的网络
   - 度量值通常为 0
   - 优先级最高

2. **静态路由 (Static)**
   - 手动配置的路由
   - 不会自动更新
   - 管理员完全控制

3. **动态路由 (Dynamic)**
   - 通过路由协议学习的路由
   - 自动更新和维护
   - 适应网络变化

### 🔌 网络接口管理

#### 接口状态

```go
type InterfaceStatus int

const (
    InterfaceStatusDown    // 接口关闭
    InterfaceStatusUp      // 接口启用
    InterfaceStatusTesting // 接口测试中
)
```

#### 接口信息

```go
type Interface struct {
    Name      string           // 接口名称 (eth0, wlan0)
    IPAddress net.IP           // IP 地址
    Netmask   net.IPMask       // 子网掩码
    Gateway   net.IP           // 默认网关
    MTU       int              // 最大传输单元
    Status    InterfaceStatus  // 接口状态
    // 统计信息
    TxPackets uint64          // 发送包数
    RxPackets uint64          // 接收包数
    TxBytes   uint64          // 发送字节数
    RxBytes   uint64          // 接收字节数
    Errors    uint64          // 错误计数
}
```

### 📦 数据包处理流程

1. **接收数据包**
   - 从网络接口接收数据包
   - 解析数据包头部信息

2. **路由查找**
   - 根据目标 IP 地址查找路由表
   - 选择最佳匹配路由

3. **转发决策**
   - 确定下一跳地址
   - 选择出接口

4. **数据包转发**
   - 修改数据包头部（如 TTL）
   - 从指定接口发送

### 🔄 路由协议

#### RIP (Routing Information Protocol)

RIP 是一种距离向量路由协议：

- **度量值**: 跳数（最大 15 跳）
- **更新间隔**: 30 秒
- **超时时间**: 180 秒
- **垃圾回收**: 120 秒

```go
type RIPConfig struct {
    Enabled           bool          // 是否启用
    UpdateInterval    time.Duration // 更新间隔
    Timeout          time.Duration // 超时时间
    GarbageCollection time.Duration // 垃圾回收时间
}
```

---

## 🎯 实践教程

### 教程 1: 基础路由配置

#### 步骤 1: 创建配置文件

创建 `config.json` 文件：

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip_address": "192.168.1.1/24",
      "mtu": 1500,
      "enabled": true
    },
    {
      "name": "eth1", 
      "ip_address": "10.0.0.1/24",
      "mtu": 1500,
      "enabled": true
    }
  ],
  "static_routes": [
    {
      "destination": "172.16.0.0/16",
      "gateway": "10.0.0.2",
      "interface": "eth1",
      "metric": 1
    }
  ],
  "rip": {
    "enabled": false,
    "update_interval": 30,
    "timeout": 180,
    "garbage_collection": 120
  }
}
```

#### 步骤 2: 启动路由器

```bash
go run main.go
```

#### 步骤 3: 使用 CLI 命令

```bash
# 查看路由表
show routes

# 查看接口状态
show interfaces

# 添加静态路由
add route 192.168.2.0/24 192.168.1.2 eth0 1

# 删除路由
del route 192.168.2.0/24
```

### 教程 2: RIP 协议配置

#### 步骤 1: 启用 RIP

修改配置文件中的 RIP 设置：

```json
{
  "rip": {
    "enabled": true,
    "update_interval": 30,
    "timeout": 180,
    "garbage_collection": 120
  }
}
```

#### 步骤 2: 启动 RIP 协议

```bash
# 在 CLI 中启动 RIP
rip start

# 查看 RIP 状态
rip show

# 停止 RIP
rip stop
```

### 教程 3: 监控和调试

#### 查看系统状态

```bash
# 查看系统统计信息
show stats

# 查看详细的接口统计
show interfaces detail
```

#### 日志调试

修改日志级别进行调试：

```go
// 在代码中设置日志级别
logger.SetLevel(logger.DEBUG)
```

---

## 🔧 高级功能

### 自定义路由算法

你可以实现自己的路由算法：

```go
// 实现自定义路由选择算法
func (rt *RoutingTable) FindBestRoute(destination net.IP) (*Route, error) {
    // 自定义路由选择逻辑
    // 例如：基于带宽、延迟等因素选择最佳路由
}
```

### 扩展路由协议

添加新的路由协议支持：

```go
// 定义新的路由协议接口
type RoutingProtocol interface {
    Start() error
    Stop() error
    UpdateRoutes() error
    GetRoutes() []*Route
}

// 实现 OSPF 协议
type OSPFProtocol struct {
    // OSPF 协议实现
}
```

### 高级监控功能

实现更详细的监控：

```go
// 扩展监控指标
type AdvancedMetrics struct {
    PacketLoss    float64
    Latency       time.Duration
    Throughput    uint64
    ErrorRate     float64
}
```

---

## 🔍 故障排除

### 常见问题

#### 1. 路由器启动失败

**症状**: 程序启动时报错
**可能原因**:
- 配置文件格式错误
- 权限不足
- 端口被占用

**解决方案**:
```bash
# 检查配置文件语法
cat config.json | jq .

# 检查权限
sudo go run main.go

# 检查端口占用
netstat -tulpn | grep :520
```

#### 2. 接口发现失败

**症状**: 无法发现网络接口
**可能原因**:
- 权限不足
- 系统不支持

**解决方案**:
```bash
# 使用管理员权限运行
sudo go run main.go

# 手动检查接口
ip addr show
```

#### 3. RIP 协议不工作

**症状**: RIP 路由不更新
**可能原因**:
- 防火墙阻止 UDP 520 端口
- 网络配置错误

**解决方案**:
```bash
# 检查防火墙设置
sudo ufw status

# 允许 RIP 端口
sudo ufw allow 520/udp
```

### 调试技巧

#### 启用详细日志

```go
// 在 main.go 中设置调试级别
logger.SetLevel(logger.DEBUG)
```

#### 使用网络工具

```bash
# 监控网络流量
tcpdump -i any port 520

# 检查路由表
ip route show

# 测试连通性
ping -c 3 192.168.1.1
```

---

## 💡 最佳实践

### 1. 配置管理

- **版本控制**: 将配置文件纳入版本控制
- **备份策略**: 定期备份配置文件
- **环境分离**: 为不同环境使用不同配置

### 2. 性能优化

- **路由表大小**: 控制路由表条目数量
- **更新频率**: 合理设置协议更新间隔
- **内存使用**: 监控内存使用情况

### 3. 安全考虑

- **访问控制**: 限制 CLI 访问权限
- **日志审计**: 记录所有配置变更
- **网络隔离**: 在隔离环境中测试

### 4. 监控和维护

- **定期检查**: 定期检查系统状态
- **性能监控**: 监控关键性能指标
- **日志分析**: 定期分析日志文件

---

## 🚀 扩展开发

### 添加新功能

#### 1. 实现负载均衡

```go
type LoadBalancer struct {
    routes []*Route
    policy LoadBalancePolicy
}

func (lb *LoadBalancer) SelectRoute(destination net.IP) *Route {
    // 实现负载均衡算法
    switch lb.policy {
    case RoundRobin:
        return lb.roundRobinSelect()
    case WeightedRoundRobin:
        return lb.weightedSelect()
    }
}
```

#### 2. 添加 OSPF 协议

```go
type OSPFProtocol struct {
    areas map[uint32]*OSPFArea
    lsdb  *LinkStateDatabase
}

func (o *OSPFProtocol) Start() error {
    // 启动 OSPF 协议
    go o.helloProtocol()
    go o.lsaFlooding()
    return nil
}
```

#### 3. 实现 QoS 功能

```go
type QoSManager struct {
    policies map[string]*QoSPolicy
    queues   map[string]*TrafficQueue
}

func (qos *QoSManager) ClassifyPacket(packet *Packet) string {
    // 数据包分类逻辑
}
```

### 贡献代码

1. **Fork 项目**
2. **创建功能分支**
3. **编写测试**
4. **提交 Pull Request**

### 测试指南

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./internal/routing

# 运行基准测试
go test -bench=. ./internal/routing
```

---

## 📚 参考资料

### 官方文档

- [Go 语言官方文档](https://golang.org/doc/)
- [Go 网络编程指南](https://golang.org/pkg/net/)

### 网络协议标准

- [RFC 2453 - RIP Version 2](https://tools.ietf.org/html/rfc2453)
- [RFC 2328 - OSPF Version 2](https://tools.ietf.org/html/rfc2328)
- [RFC 4271 - BGP-4](https://tools.ietf.org/html/rfc4271)

### 学习资源

- [计算机网络：自顶向下方法](https://book.douban.com/subject/26176870/)
- [TCP/IP 详解](https://book.douban.com/subject/1088054/)
- [路由器技术手册](https://www.cisco.com/c/en/us/support/docs/)

### 相关项目

- [GoBGP](https://github.com/osrg/gobgp) - Go 语言实现的 BGP
- [FRRouting](https://frrouting.org/) - 开源路由软件套件
- [BIRD](https://bird.network.cz/) - 互联网路由守护程序

---

## 🤝 社区和支持

### 获取帮助

- **GitHub Issues**: 报告 Bug 和功能请求
- **讨论区**: 技术讨论和经验分享
- **文档**: 查看最新文档和教程

### 贡献方式

- **代码贡献**: 提交代码改进和新功能
- **文档改进**: 完善文档和教程
- **Bug 报告**: 报告发现的问题
- **功能建议**: 提出新功能想法

---

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](../LICENSE) 文件。

---

**🎉 恭喜！你已经完成了 Router OS 的学习指南。现在开始你的网络路由学习之旅吧！**