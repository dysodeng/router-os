// 路由表管理页面JavaScript

class RoutesManager {
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

        // 加载路由列表
        await this.loadRoutes();

        // 设置定时刷新
        setInterval(() => this.loadRoutes(), 5000);

        // 绑定添加路由表单事件
        this.bindAddRouteForm();
    }

    async loadRoutes() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/routes');
            if (response.ok) {
                const data = await response.json();
                this.renderRoutes(data.routes || []);
            } else {
                console.error('加载路由列表失败:', response.status);
            }
        } catch (error) {
            console.error('加载路由列表出错:', error);
        }
    }

    renderRoutes(routes) {
        const tbody = document.getElementById('routesList');
        tbody.innerHTML = '';

        routes.forEach(route => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${route.destination || 'N/A'}</td>
                <td>${route.gateway || 'N/A'}</td>
                <td>${route.interface || 'N/A'}</td>
                <td>${route.metric || 'N/A'}</td>
                <td>${route.type || 'N/A'}</td>
                <td>
                    <button class="btn btn-sm btn-danger" 
                            onclick="routesManager.deleteRoute('${route.destination}', '${route.gateway}')">
                        删除
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    bindAddRouteForm() {
        const addButton = document.getElementById('addRouteBtn');
        if (addButton) {
            addButton.addEventListener('click', () => this.showAddRouteDialog());
        }
    }

    showAddRouteDialog() {
        const destination = prompt('请输入目标网络 (例如: 192.168.1.0/24):');
        if (!destination) return;

        const gateway = prompt('请输入网关地址 (例如: 192.168.1.1):');
        if (!gateway) return;

        const interfaceName = prompt('请输入接口名称 (例如: eth0):');
        if (!interfaceName) return;

        const metric = prompt('请输入路由优先级 (数字，可选):', '1');

        this.addRoute(destination, gateway, interfaceName, metric || '1');
    }

    async addRoute(destination, gateway, interfaceName, metric) {
        try {
            const response = await this.authManager.fetchWithAuth('/api/routes/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    destination: destination,
                    gateway: gateway,
                    interface: interfaceName,
                    metric: parseInt(metric) || 1
                })
            });

            if (response.ok) {
                await this.loadRoutes();
                this.showMessage('路由添加成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`添加路由失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('添加路由出错:', error);
            this.showMessage('添加路由失败', 'error');
        }
    }

    async deleteRoute(destination, gateway) {
        if (!confirm(`确定要删除路由 ${destination} -> ${gateway} 吗？`)) {
            return;
        }

        try {
            const response = await this.authManager.fetchWithAuth('/api/routes/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    destination: destination,
                    gateway: gateway
                })
            });

            if (response.ok) {
                await this.loadRoutes();
                this.showMessage('路由删除成功', 'success');
            } else {
                const error = await response.text();
                this.showMessage(`删除路由失败: ${error}`, 'error');
            }
        } catch (error) {
            console.error('删除路由出错:', error);
            this.showMessage('删除路由失败', 'error');
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
    window.routesManager = new RoutesManager();
});