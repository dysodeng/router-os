# Router OS API 参考文档

## 📋 目录

1. [概述](#概述)
2. [核心接口](#核心接口)
3. [路由模块](#路由模块)
4. [接口管理模块](#接口管理模块)
5. [协议模块](#协议模块)
6. [数据包处理模块](#数据包处理模块)
7. [配置模块](#配置模块)
8. [日志模块](#日志模块)
9. [监控模块](#监控模块)
10. [CLI 模块](#cli-模块)
11. [错误处理](#错误处理)
12. [使用示例](#使用示例)

---

## 🎯 概述

Router OS 提供了一套完整的 API 接口，用于构建和管理网络路由功能。本文档详细描述了各个模块的接口定义、参数说明和使用方法。

### 模块架构

```
router-os/
├── internal/
│   ├── router/          # 路由器核心
│   ├── routing/         # 路由表管理
│   ├── interfaces/      # 网络接口管理
│   ├── protocols/       # 路由协议
│   ├── packet/          # 数据包处理
│   ├── config/          # 配置管理
│   ├── logging/         # 日志系统
│   ├── monitoring/      # 系统监控
│   └── cli/             # 命令行接口
```

---

## 🔧 核心接口

### Router 接口

路由器的核心接口定义了路由器的基本操作。

```go
package router

// Router 路由器核心接口
type Router interface {
    // Start 启动路由器
    Start() error
    
    // Stop 停止路由器
    Stop() error
    
    // IsRunning 检查路由器是否运行
    IsRunning() bool
    
    // GetRoutingTable 获取路由表
    GetRoutingTable() *routing.RoutingTable
    
    // GetInterfaceManager 获取接口管理器
    GetInterfaceManager() *interfaces.Manager
    
    // ProcessPacket 处理数据包
    ProcessPacket(packet *packet.Packet) error
}

// RouterImpl 路由器实现
type RouterImpl struct {
    routingTable     *routing.RoutingTable
    interfaceManager *interfaces.Manager
    packetProcessor  *packet.Processor
    protocols        map[string]Protocol
    running          bool
    mu               sync.RWMutex
}
```

#### 方法说明

##### Start()

启动路由器及其所有组件。

```go
func (r *RouterImpl) Start() error
```

**返回值:**
- `error`: 启动失败时返回错误信息

**示例:**
```go
router := NewRouter()
if err := router.Start(); err != nil {
    log.Fatalf("Failed to start router: %v", err)
}
```

##### Stop()

停止路由器及其所有组件。

```go
func (r *RouterImpl) Stop() error
```

**返回值:**
- `error`: 停止失败时返回错误信息

##### IsRunning()

检查路由器是否正在运行。

```go
func (r *RouterImpl) IsRunning() bool
```

**返回值:**
- `bool`: true 表示运行中，false 表示已停止

---

## 🛣️ 路由模块

### RoutingTable 接口

路由表管理的核心接口。

```go
package routing

// RoutingTable 路由表接口
type RoutingTable interface {
    // AddRoute 添加路由
    AddRoute(route *Route) error
    
    // RemoveRoute 删除路由
    RemoveRoute(destination net.IPNet) error
    
    // FindRoute 查找路由
    FindRoute(destination net.IP) (*Route, error)
    
    // GetAllRoutes 获取所有路由
    GetAllRoutes() []*Route
    
    // GetRoutesByType 按类型获取路由
    GetRoutesByType(routeType RouteType) []*Route
    
    // UpdateRoute 更新路由
    UpdateRoute(route *Route) error
    
    // Clear 清空路由表
    Clear() error
}
```

### Route 结构体

路由条目的数据结构。

```go
// Route 路由条目
type Route struct {
    // Destination 目标网络
    Destination net.IPNet `json:"destination"`
    
    // Gateway 下一跳网关
    Gateway net.IP `json:"gateway"`
    
    // Interface 出接口名称
    Interface string `json:"interface"`
    
    // Metric 度量值（路由成本）
    Metric int `json:"metric"`
    
    // Type 路由类型
    Type RouteType `json:"type"`
    
    // Age 路由年龄（创建或更新时间）
    Age time.Time `json:"age"`
    
    // Source 路由来源（协议名称）
    Source string `json:"source"`
}

// RouteType 路由类型枚举
type RouteType int

const (
    RouteTypeConnected RouteType = iota  // 直连路由
    RouteTypeStatic                      // 静态路由
    RouteTypeDynamic                     // 动态路由
)
```

#### 方法说明

##### AddRoute()

向路由表添加新路由。

```go
func (rt *RoutingTableImpl) AddRoute(route *Route) error
```

**参数:**
- `route *Route`: 要添加的路由条目

**返回值:**
- `error`: 添加失败时返回错误信息

**错误情况:**
- 路由已存在
- 参数无效
- 接口不存在

**示例:**
```go
route := &Route{
    Destination: net.IPNet{
        IP:   net.ParseIP("192.168.1.0"),
        Mask: net.CIDRMask(24, 32),
    },
    Gateway:   net.ParseIP("192.168.1.1"),
    Interface: "eth0",
    Metric:    1,
    Type:      RouteTypeStatic,
}

err := routingTable.AddRoute(route)
if err != nil {
    log.Printf("Failed to add route: %v", err)
}
```

##### FindRoute()

根据目标 IP 地址查找最佳匹配路由。

```go
func (rt *RoutingTableImpl) FindRoute(destination net.IP) (*Route, error)
```

**参数:**
- `destination net.IP`: 目标 IP 地址

**返回值:**
- `*Route`: 匹配的路由条目
- `error`: 查找失败时返回错误信息

**查找规则:**
1. 最长前缀匹配
2. 相同前缀长度时，按管理距离选择
3. 相同管理距离时，按度量值选择

**示例:**
```go
destination := net.ParseIP("192.168.1.100")
route, err := routingTable.FindRoute(destination)
if err != nil {
    log.Printf("No route found for %s: %v", destination, err)
} else {
    log.Printf("Found route: %+v", route)
}
```

---

## 🔌 接口管理模块

### Manager 接口

网络接口管理的核心接口。

```go
package interfaces

// Manager 接口管理器接口
type Manager interface {
    // Start 启动接口管理器
    Start() error
    
    // Stop 停止接口管理器
    Stop()
    
    // AddInterface 添加接口
    AddInterface(iface *Interface) error
    
    // RemoveInterface 删除接口
    RemoveInterface(name string) error
    
    // GetInterface 获取指定接口
    GetInterface(name string) (*Interface, error)
    
    // GetAllInterfaces 获取所有接口
    GetAllInterfaces() map[string]*Interface
    
    // SetInterfaceStatus 设置接口状态
    SetInterfaceStatus(name string, status InterfaceStatus) error
    
    // UpdateInterfaceStats 更新接口统计信息
    UpdateInterfaceStats(name string, txPackets, rxPackets, txBytes, rxBytes, errors uint64) error
    
    // GetActiveInterfaces 获取活跃接口
    GetActiveInterfaces() []*Interface
    
    // IsRunning 检查管理器是否运行
    IsRunning() bool
}
```

### Interface 结构体

网络接口的数据结构。

```go
// Interface 网络接口
type Interface struct {
    // Name 接口名称（如 eth0, wlan0）
    Name string `json:"name"`
    
    // IPAddress IP 地址
    IPAddress net.IP `json:"ip_address"`
    
    // Netmask 子网掩码
    Netmask net.IPMask `json:"netmask"`
    
    // Gateway 默认网关
    Gateway net.IP `json:"gateway"`
    
    // MTU 最大传输单元
    MTU int `json:"mtu"`
    
    // Status 接口状态
    Status InterfaceStatus `json:"status"`
    
    // LastSeen 最后发现时间
    LastSeen time.Time `json:"last_seen"`
    
    // 统计信息
    TxPackets uint64 `json:"tx_packets"` // 发送包数
    RxPackets uint64 `json:"rx_packets"` // 接收包数
    TxBytes   uint64 `json:"tx_bytes"`   // 发送字节数
    RxBytes   uint64 `json:"rx_bytes"`   // 接收字节数
    Errors    uint64 `json:"errors"`     // 错误计数
}

// InterfaceStatus 接口状态枚举
type InterfaceStatus int

const (
    InterfaceStatusDown    InterfaceStatus = iota // 接口关闭
    InterfaceStatusUp                             // 接口启用
    InterfaceStatusTesting                        // 接口测试中
)
```

#### 方法说明

##### AddInterface()

添加新的网络接口。

```go
func (m *ManagerImpl) AddInterface(iface *Interface) error
```

**参数:**
- `iface *Interface`: 要添加的接口

**返回值:**
- `error`: 添加失败时返回错误信息

**示例:**
```go
iface := &Interface{
    Name:      "eth0",
    IPAddress: net.ParseIP("192.168.1.1"),
    Netmask:   net.CIDRMask(24, 32),
    MTU:       1500,
    Status:    InterfaceStatusUp,
}

err := manager.AddInterface(iface)
if err != nil {
    log.Printf("Failed to add interface: %v", err)
}
```

##### GetActiveInterfaces()

获取所有状态为 Up 的接口。

```go
func (m *ManagerImpl) GetActiveInterfaces() []*Interface
```

**返回值:**
- `[]*Interface`: 活跃接口列表

---

## 🔄 协议模块

### Protocol 接口

路由协议的通用接口。

```go
package protocols

// Protocol 路由协议接口
type Protocol interface {
    // Start 启动协议
    Start() error
    
    // Stop 停止协议
    Stop() error
    
    // IsRunning 检查协议是否运行
    IsRunning() bool
    
    // GetName 获取协议名称
    GetName() string
    
    // GetRoutes 获取协议学习的路由
    GetRoutes() []*routing.Route
    
    // UpdateRoutes 更新路由信息
    UpdateRoutes() error
}
```

### RIP 协议

RIP 协议的具体实现。

```go
// RIPProtocol RIP 协议实现
type RIPProtocol struct {
    config       *RIPConfig
    routingTable *routing.RoutingTable
    interfaces   map[string]*interfaces.Interface
    neighbors    map[string]*RIPNeighbor
    running      bool
    mu           sync.RWMutex
}

// RIPConfig RIP 协议配置
type RIPConfig struct {
    Enabled           bool          `json:"enabled"`
    Version           int           `json:"version"`
    UpdateInterval    time.Duration `json:"update_interval"`
    Timeout          time.Duration `json:"timeout"`
    GarbageCollection time.Duration `json:"garbage_collection"`
    Interfaces       []string      `json:"interfaces"`
    PassiveInterfaces []string      `json:"passive_interfaces"`
}

// RIPNeighbor RIP 邻居信息
type RIPNeighbor struct {
    Address  net.IP    `json:"address"`
    LastSeen time.Time `json:"last_seen"`
    Version  int       `json:"version"`
}
```

#### 方法说明

##### Start()

启动 RIP 协议。

```go
func (rip *RIPProtocol) Start() error
```

**功能:**
- 启动 RIP 更新定时器
- 开始监听 RIP 消息
- 发送初始路由更新

**返回值:**
- `error`: 启动失败时返回错误信息

##### UpdateRoutes()

更新 RIP 路由信息。

```go
func (rip *RIPProtocol) UpdateRoutes() error
```

**功能:**
- 发送路由更新消息
- 处理接收到的路由信息
- 更新路由表

---

## 📦 数据包处理模块

### Processor 接口

数据包处理的核心接口。

```go
package packet

// Processor 数据包处理器接口
type Processor interface {
    // ProcessPacket 处理数据包
    ProcessPacket(packet *Packet) error
    
    // ForwardPacket 转发数据包
    ForwardPacket(packet *Packet, route *routing.Route) error
    
    // DropPacket 丢弃数据包
    DropPacket(packet *Packet, reason string) error
}

// Packet 数据包结构
type Packet struct {
    // SourceIP 源 IP 地址
    SourceIP net.IP `json:"source_ip"`
    
    // DestinationIP 目标 IP 地址
    DestinationIP net.IP `json:"destination_ip"`
    
    // Protocol 协议类型
    Protocol int `json:"protocol"`
    
    // TTL 生存时间
    TTL int `json:"ttl"`
    
    // Data 数据载荷
    Data []byte `json:"data"`
    
    // InInterface 入接口
    InInterface string `json:"in_interface"`
    
    // Size 数据包大小
    Size int `json:"size"`
    
    // Timestamp 时间戳
    Timestamp time.Time `json:"timestamp"`
}
```

#### 方法说明

##### ProcessPacket()

处理接收到的数据包。

```go
func (p *ProcessorImpl) ProcessPacket(packet *Packet) error
```

**处理流程:**
1. 验证数据包有效性
2. 检查 TTL 值
3. 查找路由
4. 转发或丢弃数据包

**参数:**
- `packet *Packet`: 要处理的数据包

**返回值:**
- `error`: 处理失败时返回错误信息

---

## ⚙️ 配置模块

### Config 接口

配置管理的核心接口。

```go
package config

// Config 配置管理接口
type Config interface {
    // Load 加载配置
    Load(filename string) error
    
    // Save 保存配置
    Save(filename string) error
    
    // GetInterfaces 获取接口配置
    GetInterfaces() []InterfaceConfig
    
    // GetStaticRoutes 获取静态路由配置
    GetStaticRoutes() []RouteConfig
    
    // GetRIPConfig 获取 RIP 配置
    GetRIPConfig() RIPConfig
    
    // Validate 验证配置
    Validate() error
}

// RouterConfig 路由器配置
type RouterConfig struct {
    Interfaces   []InterfaceConfig `json:"interfaces"`
    StaticRoutes []RouteConfig     `json:"static_routes"`
    RIP          RIPConfig         `json:"rip"`
    Logging      LoggingConfig     `json:"logging"`
    Monitoring   MonitoringConfig  `json:"monitoring"`
}

// InterfaceConfig 接口配置
type InterfaceConfig struct {
    Name        string `json:"name"`
    IPAddress   string `json:"ip_address"`
    Gateway     string `json:"gateway,omitempty"`
    MTU         int    `json:"mtu"`
    Enabled     bool   `json:"enabled"`
    Description string `json:"description,omitempty"`
}

// RouteConfig 路由配置
type RouteConfig struct {
    Destination string `json:"destination"`
    Gateway     string `json:"gateway"`
    Interface   string `json:"interface"`
    Metric      int    `json:"metric"`
    Description string `json:"description,omitempty"`
}
```

#### 方法说明

##### Load()

从文件加载配置。

```go
func (c *ConfigImpl) Load(filename string) error
```

**参数:**
- `filename string`: 配置文件路径

**返回值:**
- `error`: 加载失败时返回错误信息

**支持格式:**
- JSON
- YAML（可扩展）

**示例:**
```go
config := NewConfig()
err := config.Load("config.json")
if err != nil {
    log.Fatalf("Failed to load config: %v", err)
}
```

---

## 📝 日志模块

### Logger 接口

日志系统的核心接口。

```go
package logging

// Logger 日志接口
type Logger interface {
    // Debug 调试级别日志
    Debug(msg string, fields ...Field)
    
    // Info 信息级别日志
    Info(msg string, fields ...Field)
    
    // Warn 警告级别日志
    Warn(msg string, fields ...Field)
    
    // Error 错误级别日志
    Error(msg string, fields ...Field)
    
    // SetLevel 设置日志级别
    SetLevel(level Level)
    
    // GetLevel 获取当前日志级别
    GetLevel() Level
}

// Level 日志级别
type Level int

const (
    DEBUG Level = iota
    INFO
    WARN
    ERROR
)

// Field 日志字段
type Field struct {
    Key   string
    Value interface{}
}
```

#### 使用示例

```go
logger := logging.NewLogger()
logger.SetLevel(logging.INFO)

// 基本日志
logger.Info("Router started")

// 带字段的日志
logger.Info("Route added", 
    logging.Field{Key: "destination", Value: "192.168.1.0/24"},
    logging.Field{Key: "gateway", Value: "192.168.1.1"},
)

// 错误日志
logger.Error("Failed to process packet", 
    logging.Field{Key: "error", Value: err.Error()},
)
```

---

## 📊 监控模块

### Monitor 接口

系统监控的核心接口。

```go
package monitoring

// Monitor 监控接口
type Monitor interface {
    // Start 启动监控
    Start() error
    
    // Stop 停止监控
    Stop() error
    
    // GetSystemMetrics 获取系统指标
    GetSystemMetrics() *SystemMetrics
    
    // GetInterfaceMetrics 获取接口指标
    GetInterfaceMetrics() map[string]*InterfaceMetrics
    
    // GetRoutingMetrics 获取路由指标
    GetRoutingMetrics() *RoutingMetrics
}

// SystemMetrics 系统指标
type SystemMetrics struct {
    Uptime       time.Duration `json:"uptime"`
    MemoryUsage  uint64        `json:"memory_usage"`
    CPUUsage     float64       `json:"cpu_usage"`
    Goroutines   int           `json:"goroutines"`
    Timestamp    time.Time     `json:"timestamp"`
}

// InterfaceMetrics 接口指标
type InterfaceMetrics struct {
    Name         string    `json:"name"`
    Status       string    `json:"status"`
    TxPackets    uint64    `json:"tx_packets"`
    RxPackets    uint64    `json:"rx_packets"`
    TxBytes      uint64    `json:"tx_bytes"`
    RxBytes      uint64    `json:"rx_bytes"`
    Errors       uint64    `json:"errors"`
    PacketLoss   float64   `json:"packet_loss"`
    Utilization  float64   `json:"utilization"`
    Timestamp    time.Time `json:"timestamp"`
}

// RoutingMetrics 路由指标
type RoutingMetrics struct {
    TotalRoutes    int       `json:"total_routes"`
    StaticRoutes   int       `json:"static_routes"`
    DynamicRoutes  int       `json:"dynamic_routes"`
    ConnectedRoutes int      `json:"connected_routes"`
    Timestamp      time.Time `json:"timestamp"`
}
```

---

## 💻 CLI 模块

### CLI 接口

命令行界面的核心接口。

```go
package cli

// CLI 命令行接口
type CLI interface {
    // Start 启动 CLI
    Start() error
    
    // Stop 停止 CLI
    Stop() error
    
    // RegisterCommand 注册命令
    RegisterCommand(cmd Command) error
    
    // ExecuteCommand 执行命令
    ExecuteCommand(input string) error
}

// Command 命令接口
type Command interface {
    // GetName 获取命令名称
    GetName() string
    
    // GetDescription 获取命令描述
    GetDescription() string
    
    // GetUsage 获取使用方法
    GetUsage() string
    
    // Execute 执行命令
    Execute(args []string) error
}

// CommandResult 命令执行结果
type CommandResult struct {
    Success bool        `json:"success"`
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
    Error   string      `json:"error,omitempty"`
}
```

### 内置命令

#### ShowRoutesCommand

显示路由表的命令。

```go
type ShowRoutesCommand struct {
    routingTable *routing.RoutingTable
}

func (cmd *ShowRoutesCommand) Execute(args []string) error {
    routes := cmd.routingTable.GetAllRoutes()
    // 格式化输出路由信息
    return nil
}
```

#### AddRouteCommand

添加路由的命令。

```go
type AddRouteCommand struct {
    routingTable *routing.RoutingTable
}

func (cmd *AddRouteCommand) Execute(args []string) error {
    // 解析参数：destination gateway interface metric
    if len(args) < 3 {
        return fmt.Errorf("usage: add route <destination> <gateway> <interface> [metric]")
    }
    
    // 创建路由并添加到路由表
    return nil
}
```

---

## ❌ 错误处理

### 错误类型

Router OS 定义了一套标准的错误类型：

```go
package errors

// RouterError 路由器错误基类
type RouterError struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Details string `json:"details,omitempty"`
}

func (e *RouterError) Error() string {
    return fmt.Sprintf("Router Error %d: %s", e.Code, e.Message)
}

// 错误代码常量
const (
    ErrCodeInvalidConfig     = 1001  // 配置无效
    ErrCodeInterfaceNotFound = 2001  // 接口未找到
    ErrCodeRouteNotFound     = 3001  // 路由未找到
    ErrCodeProtocolError     = 4001  // 协议错误
    ErrCodePacketError       = 5001  // 数据包错误
)

// 预定义错误
var (
    ErrInvalidConfig     = &RouterError{Code: ErrCodeInvalidConfig, Message: "Invalid configuration"}
    ErrInterfaceNotFound = &RouterError{Code: ErrCodeInterfaceNotFound, Message: "Interface not found"}
    ErrRouteNotFound     = &RouterError{Code: ErrCodeRouteNotFound, Message: "Route not found"}
)
```

### 错误处理最佳实践

```go
// 1. 检查特定错误类型
if err != nil {
    if routerErr, ok := err.(*errors.RouterError); ok {
        switch routerErr.Code {
        case errors.ErrCodeInterfaceNotFound:
            // 处理接口未找到错误
        case errors.ErrCodeRouteNotFound:
            // 处理路由未找到错误
        }
    }
}

// 2. 包装错误信息
func (rt *RoutingTable) AddRoute(route *Route) error {
    if route == nil {
        return fmt.Errorf("route cannot be nil")
    }
    
    if err := rt.validateRoute(route); err != nil {
        return fmt.Errorf("invalid route: %w", err)
    }
    
    // 添加路由逻辑
    return nil
}

// 3. 记录错误日志
func (r *Router) ProcessPacket(packet *Packet) error {
    route, err := r.routingTable.FindRoute(packet.DestinationIP)
    if err != nil {
        r.logger.Error("Failed to find route", 
            logging.Field{Key: "destination", Value: packet.DestinationIP.String()},
            logging.Field{Key: "error", Value: err.Error()},
        )
        return err
    }
    
    return r.forwardPacket(packet, route)
}
```

---

## 📚 使用示例

### 完整的路由器初始化示例

```go
package main

import (
    "log"
    "net"
    "time"
    
    "router-os/internal/router"
    "router-os/internal/routing"
    "router-os/internal/interfaces"
    "router-os/internal/protocols"
    "router-os/internal/config"
    "router-os/internal/logging"
)

func main() {
    // 1. 初始化日志
    logger := logging.NewLogger()
    logger.SetLevel(logging.INFO)
    
    // 2. 加载配置
    cfg := config.NewConfig()
    if err := cfg.Load("config.json"); err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }
    
    // 3. 创建路由表
    routingTable := routing.NewRoutingTable()
    
    // 4. 创建接口管理器
    interfaceManager := interfaces.NewManager()
    
    // 5. 添加接口
    for _, ifaceConfig := range cfg.GetInterfaces() {
        iface := &interfaces.Interface{
            Name:      ifaceConfig.Name,
            IPAddress: net.ParseIP(ifaceConfig.IPAddress),
            MTU:       ifaceConfig.MTU,
            Status:    interfaces.InterfaceStatusUp,
        }
        
        if err := interfaceManager.AddInterface(iface); err != nil {
            logger.Error("Failed to add interface", 
                logging.Field{Key: "interface", Value: ifaceConfig.Name},
                logging.Field{Key: "error", Value: err.Error()},
            )
        }
    }
    
    // 6. 添加静态路由
    for _, routeConfig := range cfg.GetStaticRoutes() {
        _, destNet, _ := net.ParseCIDR(routeConfig.Destination)
        route := &routing.Route{
            Destination: *destNet,
            Gateway:     net.ParseIP(routeConfig.Gateway),
            Interface:   routeConfig.Interface,
            Metric:      routeConfig.Metric,
            Type:        routing.RouteTypeStatic,
            Age:         time.Now(),
        }
        
        if err := routingTable.AddRoute(route); err != nil {
            logger.Error("Failed to add route", 
                logging.Field{Key: "destination", Value: routeConfig.Destination},
                logging.Field{Key: "error", Value: err.Error()},
            )
        }
    }
    
    // 7. 创建路由器
    r := router.NewRouter(routingTable, interfaceManager)
    
    // 8. 启动 RIP 协议（如果启用）
    ripConfig := cfg.GetRIPConfig()
    if ripConfig.Enabled {
        rip := protocols.NewRIPProtocol(routingTable, interfaceManager)
        if err := rip.Start(); err != nil {
            logger.Error("Failed to start RIP", 
                logging.Field{Key: "error", Value: err.Error()},
            )
        }
    }
    
    // 9. 启动路由器
    if err := r.Start(); err != nil {
        log.Fatalf("Failed to start router: %v", err)
    }
    
    logger.Info("Router started successfully")
    
    // 10. 等待信号退出
    // ... 信号处理代码
}
```

### 动态添加路由示例

```go
func addDynamicRoute(routingTable *routing.RoutingTable) {
    // 创建新路由
    _, destNet, _ := net.ParseCIDR("10.0.0.0/8")
    route := &routing.Route{
        Destination: *destNet,
        Gateway:     net.ParseIP("192.168.1.1"),
        Interface:   "eth0",
        Metric:      10,
        Type:        routing.RouteTypeDynamic,
        Age:         time.Now(),
        Source:      "RIP",
    }
    
    // 添加路由
    if err := routingTable.AddRoute(route); err != nil {
        log.Printf("Failed to add dynamic route: %v", err)
        return
    }
    
    log.Printf("Dynamic route added: %s via %s", 
        route.Destination.String(), route.Gateway.String())
}
```

### 数据包处理示例

```go
func processIncomingPacket(processor *packet.Processor, data []byte) {
    // 解析数据包
    pkt := &packet.Packet{
        SourceIP:      net.ParseIP("192.168.1.100"),
        DestinationIP: net.ParseIP("10.0.0.100"),
        Protocol:      6, // TCP
        TTL:           64,
        Data:          data,
        InInterface:   "eth0",
        Size:          len(data),
        Timestamp:     time.Now(),
    }
    
    // 处理数据包
    if err := processor.ProcessPacket(pkt); err != nil {
        log.Printf("Failed to process packet: %v", err)
    }
}
```

---

## 🌐 Web API 接口

Router OS 提供了完整的 RESTful API 接口，支持通过 HTTP 请求管理路由器。

### 认证

所有 API 请求都需要基本认证（Basic Authentication）。

```bash
# 示例请求头
Authorization: Basic <base64(username:password)>
```

### 路由管理 API

#### 获取路由列表

```http
GET /api/routes
```

**响应示例:**
```json
{
  "routes": [
    {
      "destination": "192.168.1.0/24",
      "gateway": "192.168.1.1",
      "iface": "eth0",
      "metric": 0,
      "proto": "kernel",
      "scope": "link",
      "src": "192.168.1.100",
      "flags": "U",
      "type": "connected",
      "status": "活跃",
      "age": "2024-01-01 10:00:00 CST",
      "ttl": "永久"
    }
  ],
  "stats": {
    "total": 5,
    "static": 2,
    "dynamic": 1,
    "connected": 2,
    "default": 0
  }
}
```

#### 添加路由

```http
POST /api/routes
Content-Type: application/json

{
  "destination": "10.0.0.0/8",
  "gateway": "192.168.1.1",
  "iface": "eth0",
  "metric": 10,
  "proto": "static",
  "scope": "universe",
  "src": "",
  "flags": "UG"
}
```

#### 删除路由

```http
DELETE /api/routes
Content-Type: application/json

{
  "destination": "10.0.0.0/8"
}
```

### 接口管理 API

#### 获取接口列表

```http
GET /api/interfaces
```

**响应示例:**
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip": "192.168.1.100",
      "status": "up",
      "mac": "00:11:22:33:44:55",
      "mtu": 1500
    }
  ]
}
```

### ARP 表管理 API

#### 获取 ARP 表

```http
GET /api/arp
```

**响应示例:**
```json
{
  "entries": [
    {
      "ip": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "interface": "eth0",
      "state": "reachable",
      "last_seen": "2024-01-01T10:00:00Z"
    }
  ]
}
```

#### 解析 IP 地址

```http
POST /api/arp/resolve
Content-Type: application/json

{
  "ip": "192.168.1.1"
}
```

### 防火墙管理 API

#### 获取防火墙规则

```http
GET /api/firewall/rules
```

#### 添加防火墙规则

```http
POST /api/firewall/rules
Content-Type: application/json

{
  "action": "ACCEPT",
  "protocol": "tcp",
  "source": "192.168.1.0/24",
  "destination": "0.0.0.0/0",
  "port": "80"
}
```

### DHCP 管理 API

#### 获取 DHCP 租约

```http
GET /api/dhcp/leases
```

**响应示例:**
```json
{
  "leases": [
    {
      "ip": "192.168.1.100",
      "mac": "00:11:22:33:44:55",
      "hostname": "client1",
      "lease_time": "2024-01-01T12:00:00Z",
      "expires": "2024-01-01T13:00:00Z"
    }
  ]
}
```

### 端口管理 API

#### 获取端口列表

```http
GET /api/ports
```

**响应示例:**
```json
[
  {
    "name": "eth0",
    "role": "lan",
    "status": 1,
    "ip_address": "192.168.1.1",
    "netmask": "255.255.255.0",
    "gateway": "192.168.1.1",
    "mtu": 1500,
    "speed": 1000,
    "duplex": "full",
    "tx_packets": 1000,
    "rx_packets": 2000,
    "tx_bytes": 1048576,
    "rx_bytes": 2097152,
    "tx_errors": 0,
    "rx_errors": 0,
    "tx_dropped": 0,
    "rx_dropped": 0
  }
]
```

#### 更新端口角色

```http
POST /api/ports/role
Content-Type: application/json

{
  "interface": "eth0",
  "role": "wan"
}
```

#### 批量更新端口角色

```http
POST /api/ports/batch
Content-Type: application/json

{
  "updates": [
    {"interface": "eth0", "role": "wan"},
    {"interface": "eth1", "role": "lan"}
  ]
}
```

#### 获取端口拓扑

```http
GET /api/ports/topology
```

### 系统监控 API

#### 获取系统状态

```http
GET /api/monitor/system
```

**响应示例:**
```json
{
  "uptime": "72h30m15s",
  "memory_usage": 134217728,
  "cpu_usage": 15.5,
  "goroutines": 25,
  "timestamp": "2024-01-01T10:00:00Z"
}
```

#### 获取接口统计

```http
GET /api/monitor/interfaces
```

#### 获取路由统计

```http
GET /api/monitor/routes
```

### VPN 管理 API

#### 获取 VPN 状态

```http
GET /api/vpn/status
```

#### 获取 VPN 客户端列表

```http
GET /api/vpn/clients
```

### QoS 管理 API

#### 获取 QoS 规则

```http
GET /api/qos/rules
```

#### 添加 QoS 规则

```http
POST /api/qos/rules
Content-Type: application/json

{
  "name": "high_priority",
  "priority": 1,
  "bandwidth": "10Mbps",
  "source": "192.168.1.0/24"
}
```

### 错误响应

API 错误响应遵循标准 HTTP 状态码：

```json
{
  "error": "Invalid request",
  "code": 400,
  "details": "Missing required field: destination"
}
```

**常见状态码:**
- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `401 Unauthorized`: 认证失败
- `404 Not Found`: 资源不存在
- `405 Method Not Allowed`: 方法不允许
- `500 Internal Server Error`: 服务器内部错误

---

**📖 本 API 参考文档提供了 Router OS 的完整接口说明，更多使用示例请参考 [examples](../examples/) 目录。**