package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// WebConfig Web服务配置
type WebConfig struct {
	Enabled     bool   `json:"enabled"`
	Port        int    `json:"port"`
	Host        string `json:"host"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	EnableHTTPS bool   `json:"enable_https"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
}

// DHCPConfig DHCP服务配置
type DHCPConfig struct {
	Enabled    bool     `json:"enabled"`
	Interface  string   `json:"interface"`
	StartIP    string   `json:"start_ip"`
	EndIP      string   `json:"end_ip"`
	SubnetMask string   `json:"subnet_mask"`
	Gateway    string   `json:"gateway"`
	DNSServers []string `json:"dns_servers"`
	LeaseTime  int      `json:"lease_time"` // 秒
}

// VPNConfig VPN服务配置
type VPNConfig struct {
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
}

// FirewallConfig 防火墙配置
type FirewallConfig struct {
	Enabled       bool   `json:"enabled"`
	DefaultPolicy string `json:"default_policy"`
}

// QoSConfig QoS配置
type QoSConfig struct {
	Enabled          bool   `json:"enabled"`
	DefaultBandwidth string `json:"default_bandwidth"`
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level string `json:"level"`
	File  string `json:"file"`
}

// AppConfig 应用配置
type AppConfig struct {
	Web      WebConfig      `json:"web"`
	DHCP     DHCPConfig     `json:"dhcp"`
	VPN      VPNConfig      `json:"vpn"`
	Firewall FirewallConfig `json:"firewall"`
	QoS      QoSConfig      `json:"qos"`
	Logging  LoggingConfig  `json:"logging"`
}

// LoadAppConfig 加载应用配置
func LoadAppConfig(configFile string) (*AppConfig, error) {
	// 如果配置文件不存在，返回默认配置
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return getDefaultAppConfig(), nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	var config AppConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	return &config, nil
}

// getDefaultAppConfig 获取默认应用配置
func getDefaultAppConfig() *AppConfig {
	return &AppConfig{
		Web: WebConfig{
			Enabled:     true, // 默认启用
			Port:        8080,
			Host:        "0.0.0.0",
			Username:    "admin",
			Password:    "admin123",
			EnableHTTPS: false,
			CertFile:    "",
			KeyFile:     "",
		},
		DHCP: DHCPConfig{
			Enabled:    false, // 默认关闭
			Interface:  "eth0",
			StartIP:    "192.168.1.100",
			EndIP:      "192.168.1.200",
			SubnetMask: "255.255.255.0",
			Gateway:    "192.168.1.1",
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
			LeaseTime:  3600,
		},
		VPN: VPNConfig{
			Enabled:  false,
			Port:     1194,
			Protocol: "udp",
			Network:  "10.8.0.0/24",
		},
		Firewall: FirewallConfig{
			Enabled:       true,
			DefaultPolicy: "DROP",
		},
		QoS: QoSConfig{
			Enabled:          true,
			DefaultBandwidth: "100Mbps",
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "/var/log/router-os.log",
		},
	}
}

// SaveAppConfig 保存应用配置
func SaveAppConfig(config *AppConfig, configFile string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	return nil
}

// ConvertDHCPConfigToDuration 将DHCP配置中的租约时间转换为Duration
func (c *DHCPConfig) GetLeaseTimeDuration() time.Duration {
	return time.Duration(c.LeaseTime) * time.Second
}
