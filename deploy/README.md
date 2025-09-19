# Router OS 部署指南

本文档详细介绍如何将Router OS部署到Linux系统并设置开机自启动。

## 目录

- [系统要求](#系统要求)
- [快速部署](#快速部署)
- [手动部署](#手动部署)
- [配置说明](#配置说明)
- [服务管理](#服务管理)
- [网络配置](#网络配置)
- [故障排除](#故障排除)
- [卸载说明](#卸载说明)

## 系统要求

### 支持的操作系统
- Ubuntu 18.04+ / Debian 9+
- CentOS 7+ / RHEL 7+
- Fedora 30+
- 其他支持systemd的Linux发行版

### 硬件要求
- CPU: x86_64架构
- 内存: 最少512MB，推荐1GB+
- 存储: 最少100MB可用空间
- 网络: 至少一个网络接口

### 软件依赖
- systemd (用于服务管理)
- iproute2 (网络配置)
- iptables (防火墙配置)
- tar, gzip (解压部署包)

## 快速部署

### 方法一：使用Makefile（推荐）

```bash
# 1. 克隆或下载项目
git clone <repository-url>
cd router-os

# 2. 一键部署（需要root权限）
sudo make deploy
```

这个命令会自动完成：
- 构建Linux版本的可执行文件
- 打包部署文件
- 安装到系统目录
- 配置systemd服务
- 设置网络环境
- 启用开机自启动

### 方法二：使用部署包

```bash
# 1. 下载部署包
wget <deployment-package-url>/router-os-deploy.tar.gz

# 2. 解压部署包
tar -xzf router-os-deploy.tar.gz
cd router-os-deploy

# 3. 运行安装脚本
sudo ./deploy{"rewrite": false, "file_path": "/Users/dysodeng/project/go/router-os/deploy/DEPLOYMENT.md", "content":