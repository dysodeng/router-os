// 网络接口管理页面JavaScript

class InterfacesManager {
    constructor() {
        this.authManager = new AuthManager();
        this.init();
    }

    async init() {
        // 检查认证状态
        if (!await this.authManager.checkAuth()) {
            return;
        }

        // 显示页面内容
        document.getElementById('auth-check').style.display = 'none';
        document.getElementById('page-content').style.display = 'block';

        // 加载接口列表
        await this.loadInterfaces();

        // 设置定时刷新
        setInterval(() => this.loadInterfaces(), 5000);
    }

    async loadInterfaces() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/interfaces');
            if (response.ok) {
                const data = await response.json();
                this.renderInterfaces(data.interfaces || []);
            } else {
                console.error('加载接口列表失败:', response.status);
            }
        } catch (error) {
            console.error('加载接口列表出错:', error);
        }
    }

    renderInterfaces(interfaces) {
        const tbody = document.getElementById('interfacesList');
        tbody.innerHTML = '';

        if (!interfaces || interfaces.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td colspan="5" style="text-align: center; color: #666;">
                    暂无网络接口数据
                </td>
            `;
            tbody.appendChild(row);
            return;
        }

        interfaces.forEach(iface => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${iface.name || 'N/A'}</td>
                <td>${iface.ip || 'N/A'}</td>
                <td>
                    <span class="status ${iface.status === 'up' ? 'status-up' : 'status-down'}">
                        ${iface.status === 'up' ? '启用' : '禁用'}
                    </span>
                </td>
                <td>${iface.mac || 'N/A'}</td>
                <td>
                    <button class="btn btn-sm ${iface.status === 'up' ? 'btn-warning' : 'btn-success'}" 
                            onclick="interfacesManager.toggleInterface('${iface.name}', '${iface.status}')">
                        ${iface.status === 'up' ? '禁用' : '启用'}
                    </button>
                    <button class="btn btn-sm btn-primary" 
                            onclick="interfacesManager.showUpdateDialog('${iface.name}', '${iface.ip}')">
                        配置
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    async toggleInterface(name, currentStatus) {
        const newStatus = currentStatus === 'up' ? 'down' : 'up';
        
        try {
            const response = await this.authManager.fetchWithAuth('/api/interfaces/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    status: newStatus
                })
            });

            if (response.ok) {
                await this.loadInterfaces();
                this.showMessage(`接口 ${name} 已${newStatus === 'up' ? '启用' : '禁用'}`, 'success');
            } else {
                const error = await response.text();
                this.showMessage(`操作失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('切换接口状态出错:', error);
            this.showMessage('操作失败', 'error');
        }
    }

    showUpdateDialog(name, currentIP) {
        const newIP = prompt(`请输入接口 ${name} 的新IP地址:`, currentIP);
        if (newIP && newIP !== currentIP) {
            this.updateInterface(name, newIP);
        }
    }

    async updateInterface(name, ip) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/interfaces/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    name: name,
                    ip: ip
                })
            });

            if (response.ok) {
                await this.loadInterfaces();
                this.showMessage(`接口 ${name} IP地址已更新`, 'success');
            } else {
                const error = await response.text();
                this.showMessage(`更新失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('更新接口出错:', error);
            this.showMessage('更新失败', 'error');
        }
    }

    showMessage(message, type) {
        // 创建消息提示
        const messageDiv = document.createElement('div');
        messageDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'}`;
        messageDiv.textContent = message;
        messageDiv.style.position = 'fixed';
        messageDiv.style.top = '20px';
        messageDiv.style.right = '20px';
        messageDiv.style.zIndex = '9999';

        document.body.appendChild(messageDiv);

        // 3秒后自动移除
        setTimeout(() => {
            if (messageDiv.parentNode) {
                messageDiv.parentNode.removeChild(messageDiv);
            }
        }, 3000);
    }
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    window.interfacesManager = new InterfacesManager();
});