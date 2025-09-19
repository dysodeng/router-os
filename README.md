# Router OS

一个使用 Go 语言实现的简单路由器操作系统，支持基本的路由功能、协议管理和网络接口管理。

## 功能特性

- **路由表管理**: 支持静态路由和动态路由
- **协议支持**: 
  - 静态路由配置
  - RIP (Routing Information Protocol) 协议
- **网络接口管理**: 自动发现和管理网络接口
- **数据包处理**: 基本的数据包转发和处理逻辑
- **配置管理**: JSON 格式的配置文件支持
- **CLI 接口**: 命令行管理界面
- **日志记录**: 分级日志系统
- **系统监控**: 实时系统状态监控

## 项目结构

```
router-os/
├── main.go                     # 主程序入口
├── go.mod                      # Go 模块文件
├── examples/                   # 示例程序
│   └── basic_test.go          # 基本功能测试
├── internal/                   # 内部包
│   ├── router/                # 路由器核心
│   │   └── router.go
│   ├── routing/               # 路由表管理
│   │   └── table.go
│   ├── interfaces/            # 网络接口管理
│   │   └── manager.go
│   ├── packet/                # 数据包处理
│   │   └── processor.go
│   ├── protocols/             # 路由协议
│   │   ├── static.go          # 静态路由
│   │   └── rip.go             # RIP 协议
│   ├── config/                # 配置管理
│   │   └── config.go
│   ├── cli/                   # 命令行接口
│   │   └── cli.go
│   ├── logging/               # 日志系统
│   │   └── logger.go
│   └── monitoring/            # 系统监控
│       └── monitor.go
└── README.md                  # 项目文档
```

## 快速开始

### 1. 初始化项目

```bash
cd router-os
go mod init router-os
go mod tidy
```

### 2. 运行路由器

```bash
go run main.go
```

### 3. 运行测试示例

```bash
go run examples/basic_test.go
```

## 配置文件

路由器使用 JSON 格式的配置文件，默认位置为 `config.json`：

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip_address": "10.0.0.1/24",
      "mtu": 1500,
      "enabled": true
    }
  ],
  "static_routes": [
    {
      "destination": "192.168.1.0/24",
      "gateway": "10.0.0.1",
      "interface": "eth0",
      "metric": 1
    }
  ],
  "rip": {
    "enabled": true,
    "update_interval": 30,
    "timeout": 180,
    "garbage_collection": 120
  }
}
```

## CLI 命令

启动路由器后，可以使用以下 CLI 命令：

- `show routes` - 显示路由表
- `show interfaces` - 显示网络接口状态
- `show stats` - 显示系统统计信息
- `add route <dest> <gateway> <interface> [metric]` - 添加静态路由
- `del route <dest>` - 删除路由
- `rip start` - 启动 RIP 协议
- `rip stop` - 停止 RIP 协议
- `rip show` - 显示 RIP 状态
- `help` - 显示帮助信息
- `exit` - 退出程序

## 日志级别

支持以下日志级别：
- `DEBUG` - 调试信息
- `INFO` - 一般信息
- `WARN` - 警告信息
- `ERROR` - 错误信息

## 监控功能

系统提供以下监控指标：
- 系统运行时间
- 内存使用情况
- Goroutine 数量
- 路由表统计
- 接口统计信息

## 开发说明

### 添加新的路由协议

1. 在 `internal/protocols/` 目录下创建新的协议文件
2. 实现协议的启动、停止和更新逻辑
3. 在路由器中注册新协议

### 扩展 CLI 命令

1. 在 `internal/cli/cli.go` 中添加新的命令处理函数
2. 更新命令解析逻辑
3. 添加相应的帮助信息

### 自定义数据包处理

1. 修改 `internal/packet/processor.go` 中的处理逻辑
2. 添加新的数据包类型支持
3. 实现相应的转发规则

## 注意事项

- 这是一个教学和演示用的简化路由器实现
- 不建议在生产环境中使用
- 某些功能可能需要管理员权限才能正常工作
- 实际的网络数据包处理需要更复杂的实现

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。