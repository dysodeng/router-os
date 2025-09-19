package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// InterfaceConfig 接口配置
type InterfaceConfig struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	Netmask   string `json:"netmask"`
	Gateway   string `json:"gateway,omitempty"`
	MTU       int    `json:"mtu"`
	Enabled   bool   `json:"enabled"`
}

// StaticRouteConfig 静态路由配置
type StaticRouteConfig struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// RIPConfig RIP协议配置
type RIPConfig struct {
	Enabled     bool     `json:"enabled"`
	Interfaces  []string `json:"interfaces"`
	UpdateTimer int      `json:"update_timer"` // 秒
	Timeout     int      `json:"timeout"`      // 秒
}

// RouterConfig 路由器配置
type RouterConfig struct {
	Hostname     string              `json:"hostname"`
	Interfaces   []InterfaceConfig   `json:"interfaces"`
	StaticRoutes []StaticRouteConfig `json:"static_routes"`
	RIP          RIPConfig           `json:"rip"`
	LogLevel     string              `json:"log_level"`
	LogFile      string              `json:"log_file"`
}

// ConfigManager 配置管理器
type ConfigManager struct {
	config     *RouterConfig
	configFile string
	mu         sync.RWMutex
}

// NewConfigManager 创建配置管理器
func NewConfigManager(configFile string) *ConfigManager {
	return &ConfigManager{
		configFile: configFile,
		config:     getDefaultConfig(),
	}
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *RouterConfig {
	return &RouterConfig{
		Hostname: "router-os",
		Interfaces: []InterfaceConfig{
			{
				Name:      "eth0",
				IPAddress: "192.168.1.1",
				Netmask:   "255.255.255.0",
				MTU:       1500,
				Enabled:   true,
			},
		},
		StaticRoutes: []StaticRouteConfig{},
		RIP: RIPConfig{
			Enabled:     false,
			Interfaces:  []string{},
			UpdateTimer: 30,
			Timeout:     180,
		},
		LogLevel: "info",
		LogFile:  "/var/log/router-os.log",
	}
}

// LoadConfig 加载配置文件
func (cm *ConfigManager) LoadConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查配置文件是否存在
	if _, err := os.Stat(cm.configFile); os.IsNotExist(err) {
		// 配置文件不存在，使用默认配置并保存
		return cm.saveConfigUnsafe()
	}

	// 读取配置文件
	data, err := ioutil.ReadFile(cm.configFile)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON配置
	var config RouterConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	cm.config = &config
	return nil
}

// SaveConfig 保存配置文件
func (cm *ConfigManager) SaveConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.saveConfigUnsafe()
}

// saveConfigUnsafe 保存配置（不加锁）
func (cm *ConfigManager) saveConfigUnsafe() error {
	// 序列化配置
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	// 写入文件
	if err := ioutil.WriteFile(cm.configFile, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// GetConfig 获取配置
func (cm *ConfigManager) GetConfig() *RouterConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 返回配置的副本
	configCopy := *cm.config
	return &configCopy
}

// SetHostname 设置主机名
func (cm *ConfigManager) SetHostname(hostname string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.Hostname = hostname
}

// AddInterface 添加接口配置
func (cm *ConfigManager) AddInterface(iface InterfaceConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查是否已存在
	for i, existingIface := range cm.config.Interfaces {
		if existingIface.Name == iface.Name {
			cm.config.Interfaces[i] = iface
			return
		}
	}

	// 添加新接口
	cm.config.Interfaces = append(cm.config.Interfaces, iface)
}

// RemoveInterface 删除接口配置
func (cm *ConfigManager) RemoveInterface(name string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, iface := range cm.config.Interfaces {
		if iface.Name == name {
			cm.config.Interfaces = append(cm.config.Interfaces[:i], cm.config.Interfaces[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("接口 %s 不存在", name)
}

// AddStaticRoute 添加静态路由配置
func (cm *ConfigManager) AddStaticRoute(route StaticRouteConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查是否已存在
	for i, existingRoute := range cm.config.StaticRoutes {
		if existingRoute.Destination == route.Destination &&
			existingRoute.Gateway == route.Gateway &&
			existingRoute.Interface == route.Interface {
			cm.config.StaticRoutes[i] = route
			return
		}
	}

	// 添加新路由
	cm.config.StaticRoutes = append(cm.config.StaticRoutes, route)
}

// RemoveStaticRoute 删除静态路由配置
func (cm *ConfigManager) RemoveStaticRoute(destination, gateway, iface string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, route := range cm.config.StaticRoutes {
		if route.Destination == destination &&
			route.Gateway == gateway &&
			route.Interface == iface {
			cm.config.StaticRoutes = append(cm.config.StaticRoutes[:i], cm.config.StaticRoutes[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("静态路由不存在")
}

// SetRIPConfig 设置RIP配置
func (cm *ConfigManager) SetRIPConfig(ripConfig RIPConfig) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.RIP = ripConfig
}

// SetLogConfig 设置日志配置
func (cm *ConfigManager) SetLogConfig(level, file string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.config.LogLevel = level
	cm.config.LogFile = file
}
