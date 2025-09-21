// 路由表管理页面JavaScript

class RoutesManager {
    constructor() {
        this.authManager = window.authManager;
        this.allRoutes = [];
        this.currentFilter = 'all';
    }

    async init() {
        if (!this.authManager.isAuthenticated()) {
            window.location.href = '/login';
            return;
        }

        await this.loadRoutes();
        
        // 设置定时刷新
        setInterval(() => {
            this.loadRoutes();
        }, 30000); // 30秒刷新一次

        // 绑定添加路由表单
        this.bindAddRouteForm();
        
        // 绑定过滤器
        this.bindFilters();
    }

    async loadRoutes() {
        try {
            const response = await this.authManager.fetchWithAuth('/api/routes');
            if (response.ok) {
                const data = await response.json();
                this.allRoutes = data.routes || [];
                this.renderRoutes(this.allRoutes);
                this.updateStats(data.stats || {});
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

        if (!routes || routes.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td colspan="13" style="text-align: center; color: #666;">暂无路由数据</td>
            `;
            tbody.appendChild(row);
            return;
        }

        routes.forEach(route => {
            // 调试信息：打印路由数据
            console.log('Route data:', route);
            const row = document.createElement('tr');
            
            // 根据状态设置行的样式
            let statusClass = '';
            let statusColor = '';
            switch (route.status) {
                case '过期':
                    statusClass = 'route-expired';
                    statusColor = 'color: #dc3545;';
                    break;
                case '即将过期':
                    statusClass = 'route-expiring';
                    statusColor = 'color: #fd7e14;';
                    break;
                default:
                    statusColor = 'color: #28a745;';
            }
            
            row.className = statusClass;
            row.innerHTML = `
                <td>${route.destination || 'N/A'}</td>
                <td>${route.gateway || 'N/A'}</td>
                <td>${route.iface || 'N/A'}</td>
                <td>${route.metric || 'N/A'}</td>
                <td><span class="route-proto-badge">${route.proto || 'N/A'}</span></td>
                <td><span class="route-scope-badge">${route.scope || 'N/A'}</span></td>
                <td>${route.src || 'N/A'}</td>
                <td><span class="route-flags-badge">${route.flags || 'N/A'}</span></td>
                <td><span class="route-type-badge route-type-${route.type || 'unknown'}">${route.type || 'N/A'}</span></td>
                <td>${route.age || 'N/A'}</td>
                <td>${route.ttl || 'N/A'}</td>
                <td><span style="${statusColor}">${route.status || 'N/A'}</span></td>
                <td>
                    <button class="btn btn-sm btn-danger" 
                            onclick="routesManager.deleteRoute('${route.destination}', '${route.gateway}')"
                            ${route.type === '直连' ? 'disabled title="直连路由不能删除"' : ''}>
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
                    iface: interfaceName,
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

    updateStats(stats) {
        // 更新统计信息
        document.getElementById('totalRoutes').textContent = stats.total || 0;
        document.getElementById('staticRoutes').textContent = stats.static || 0;
        document.getElementById('dynamicRoutes').textContent = stats.dynamic || 0;
        document.getElementById('connectedRoutes').textContent = stats.connected || 0;
    }

    bindFilters() {
        // 绑定过滤器按钮
        const filterButtons = document.querySelectorAll('.filter-btn');
        filterButtons.forEach(btn => {
            btn.addEventListener('click', (e) => {
                // 移除所有按钮的active类
                filterButtons.forEach(b => b.classList.remove('active'));
                // 添加当前按钮的active类
                e.target.classList.add('active');
                
                // 设置当前过滤器
                this.currentFilter = e.target.dataset.filter;
                
                // 应用过滤
                this.applyFilter();
            });
        });

        // 绑定搜索框
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                this.applyFilter();
            });
        }
    }

    applyFilter() {
        let filteredRoutes = [...this.allRoutes];

        // 按类型过滤
        if (this.currentFilter !== 'all') {
            filteredRoutes = filteredRoutes.filter(route => 
                route.type === this.currentFilter
            );
        }

        // 按搜索关键词过滤
        const searchInput = document.getElementById('searchInput');
        if (searchInput && searchInput.value.trim()) {
            const keyword = searchInput.value.trim().toLowerCase();
            filteredRoutes = filteredRoutes.filter(route => 
                (route.destination && route.destination.toLowerCase().includes(keyword)) ||
                (route.gateway && route.gateway.toLowerCase().includes(keyword)) ||
                (route.iface && route.iface.toLowerCase().includes(keyword))
            );
        }

        // 渲染过滤后的路由
        this.renderRoutes(filteredRoutes);
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
    window.routesManager.init();
});