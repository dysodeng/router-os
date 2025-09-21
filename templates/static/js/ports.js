// 端口管理JavaScript
class PortManager {
    constructor() {
        this.ports = [];
        this.draggedPort = null;
        this.authManager = window.authManager;
        this.init();
    }

    async init() {
        // 等待认证完成
        if (!this.authManager || !this.authManager.isAuthenticated()) {
            return;
        }
        
        await this.loadPorts();
        this.setupDragAndDrop();
        this.setupEventListeners();
    }

    // 将数字角色转换为字符串
    roleToString(role) {
        switch (role) {
            case 0: return 'unassigned';
            case 1: return 'WAN';
            case 2: return 'LAN';
            case 3: return 'DMZ';
            default: return 'unknown';
        }
    }

    // 加载端口数据
    async loadPorts() {
        try {
            this.showLoading(true);
            const response = await this.authManager.fetchWithAuth('/api/ports');
            if (!response || !response.ok) {
                throw new Error('Failed to load ports');
            }
            this.ports = await response.json();
            this.renderPorts();
            this.updateStats();
        } catch (error) {
            console.error('Error loading ports:', error);
            this.showError('加载端口信息失败: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }

    // 渲染端口到对应区域
    renderPorts() {
        // 清空所有区域
        const zones = ['wan-zone', 'lan-zone', 'unassigned-zone'];
        zones.forEach(zoneId => {
            const zone = document.getElementById(zoneId);
            const placeholder = zone.querySelector('.drop-placeholder');
            // 移除所有端口项，保留占位符
            const portItems = zone.querySelectorAll('.port-item');
            portItems.forEach(item => item.remove());
        });

        // 渲染端口到对应区域
        this.ports.forEach(port => {
            const portElement = this.createPortElement(port);
            const targetZone = this.getZoneByRole(port.role);
            if (targetZone) {
                targetZone.appendChild(portElement);
            }
        });

        // 更新占位符显示状态
        this.updatePlaceholders();
        
        // 渲染表格
        this.renderTable();
    }

    // 创建端口元素
    createPortElement(port) {
        const portDiv = document.createElement('div');
        portDiv.className = 'port-item';
        portDiv.draggable = true;
        portDiv.dataset.portName = port.name;
        
        portDiv.innerHTML = `
            <div class="port-info">
                <div>
                    <div class="port-name">${port.name}</div>
                    <div class="port-ip">${port.ip_address || 'N/A'}</div>
                </div>
                <div class="port-status ${port.status === 1 ? 'up' : 'down'}">
                    ${port.status === 1 ? 'UP' : 'DOWN'}
                </div>
            </div>
        `;

        return portDiv;
    }

    // 根据角色获取对应区域
    getZoneByRole(role) {
        // 如果是数字，先转换为字符串
        const roleStr = typeof role === 'number' ? this.roleToString(role) : role;
        switch (roleStr) {
            case 'WAN':
                return document.getElementById('wan-zone');
            case 'LAN':
                return document.getElementById('lan-zone');
            default:
                return document.getElementById('unassigned-zone');
        }
    }

    // 更新占位符显示状态
    updatePlaceholders() {
        const zones = [
            { id: 'wan-zone', role: 'WAN' },
            { id: 'lan-zone', role: 'LAN' },
            { id: 'unassigned-zone', role: 'UNASSIGNED' }
        ];

        zones.forEach(zone => {
            const zoneElement = document.getElementById(zone.id);
            const placeholder = zoneElement.querySelector('.drop-placeholder');
            const portItems = zoneElement.querySelectorAll('.port-item');
            
            if (portItems.length > 0) {
                placeholder.style.display = 'none';
            } else {
                placeholder.style.display = 'flex';
            }
        });
    }

    // 设置拖拽功能
    setupDragAndDrop() {
        // 为所有拖放区域添加事件监听器
        const dropZones = document.querySelectorAll('.port-drop-zone');
        dropZones.forEach(zone => {
            zone.addEventListener('dragover', this.handleDragOver.bind(this));
            zone.addEventListener('drop', this.handleDrop.bind(this));
            zone.addEventListener('dragenter', this.handleDragEnter.bind(this));
            zone.addEventListener('dragleave', this.handleDragLeave.bind(this));
        });

        // 使用事件委托为端口项添加拖拽事件
        document.addEventListener('dragstart', (e) => {
            if (e.target.classList.contains('port-item')) {
                this.handleDragStart(e);
            }
        });

        document.addEventListener('dragend', (e) => {
            if (e.target.classList.contains('port-item')) {
                this.handleDragEnd(e);
            }
        });
    }

    handleDragStart(e) {
        this.draggedPort = e.target;
        e.target.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/html', e.target.outerHTML);
    }

    handleDragEnd(e) {
        e.target.classList.remove('dragging');
        this.draggedPort = null;
        
        // 清理所有拖放区域的样式
        const dropZones = document.querySelectorAll('.port-drop-zone');
        dropZones.forEach(zone => {
            zone.classList.remove('drag-over');
        });
    }

    handleDragOver(e) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
    }

    handleDragEnter(e) {
        e.preventDefault();
        e.currentTarget.classList.add('drag-over');
    }

    handleDragLeave(e) {
        // 只有当离开整个拖放区域时才移除样式
        if (!e.currentTarget.contains(e.relatedTarget)) {
            e.currentTarget.classList.remove('drag-over');
        }
    }

    async handleDrop(e) {
        e.preventDefault();
        e.currentTarget.classList.remove('drag-over');

        if (!this.draggedPort) {
            console.warn('No dragged port found');
            return;
        }

        const targetZone = e.currentTarget;
        const portName = this.draggedPort.dataset.portName;
        
        if (!portName) {
            console.error('Port name not found in dragged element');
            this.showError('无法获取端口名称');
            return;
        }
        
        // 确定目标角色
        let targetRole;
        if (targetZone.id === 'wan-zone') {
            targetRole = 'WAN';
        } else if (targetZone.id === 'lan-zone') {
            targetRole = 'LAN';
        } else if (targetZone.id === 'unassigned-zone') {
            targetRole = 'UNASSIGNED';
        } else {
            console.error('Unknown target zone:', targetZone.id);
            this.showError('无效的目标区域');
            return;
        }

        // 检查是否是相同角色（避免不必要的操作）
        const currentPort = this.ports.find(p => p.name === portName);
        if (currentPort && this.roleToString(currentPort.role) === targetRole) {
            console.log('Port already has the target role');
            return;
        }

        try {
            // 显示加载状态
            this.showLoading(true);
            
            // 更新端口角色
            await this.updatePortRole(portName, targetRole);
            
            // 重新加载端口数据以确保同步（这会重新渲染DOM）
            await this.loadPorts();
            
            this.showSuccess(`端口 ${portName} 已成功分配为 ${targetRole} 角色`);
        } catch (error) {
            console.error('Error updating port role:', error);
            let errorMessage = '更新端口角色失败';
            if (error.message) {
                errorMessage += ': ' + error.message;
            }
            this.showError(errorMessage);
            // 发生错误时也重新加载，确保UI状态正确
            try {
                await this.loadPorts();
            } catch (loadError) {
                console.error('Error reloading ports after failure:', loadError);
            }
        } finally {
            this.showLoading(false);
        }
    }

    // 更新端口角色
    async updatePortRole(portName, role) {
        const response = await this.authManager.fetchWithAuth('/api/ports/role', {
            method: 'POST',
            body: JSON.stringify({
                interface_name: portName,
                role: role
            })
        });

        if (!response || !response.ok) {
            throw new Error('Failed to update port role');
        }

        return response.json();
    }

    // 渲染表格
    renderTable() {
        const tbody = document.getElementById('ports-table-body');
        tbody.innerHTML = '';

        this.ports.forEach(port => {
            const roleStr = this.roleToString(port.role);
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${port.name}</td>
                <td><span class="role-badge ${roleStr.toLowerCase()}">${roleStr}</span></td>
                <td><span class="port-status ${port.status === 1 ? 'up' : 'down'}">${port.status === 1 ? 'UP' : 'DOWN'}</span></td>
                <td>${port.ip_address || 'N/A'}</td>
                <td>${port.netmask || 'N/A'}</td>
                <td>${port.gateway || 'N/A'}</td>
                <td>${port.mtu || 'N/A'}</td>
                <td>${port.tx_packets || 0}</td>
                <td>${port.rx_packets || 0}</td>
                <td>${port.tx_errors + port.rx_errors || 0}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="portManager.configurePort('${port.name}')">
                        配置
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    // 更新统计信息
    updateStats() {
        const stats = {
            wan: this.ports.filter(p => this.roleToString(p.role) === 'WAN').length,
            lan: this.ports.filter(p => this.roleToString(p.role) === 'LAN').length,
            unassigned: this.ports.filter(p => this.roleToString(p.role) === 'unassigned').length,
            total: this.ports.length
        };

        document.getElementById('wan-count').textContent = stats.wan;
        document.getElementById('lan-count').textContent = stats.lan;
        document.getElementById('unassigned-count').textContent = stats.unassigned;
        document.getElementById('total-count').textContent = stats.total;
    }

    // 配置端口
    configurePort(portName) {
        const port = this.ports.find(p => p.Name === portName);
        if (!port) return;

        document.getElementById('port-name').value = port.Name;
        document.getElementById('port-role').value = port.Role || 'UNASSIGNED';
        document.getElementById('port-config-modal').style.display = 'block';
    }

    // 设置事件监听器
    setupEventListeners() {
        // 端口配置表单提交
        document.getElementById('port-config-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const portName = document.getElementById('port-name').value;
            const newRole = document.getElementById('port-role').value;

            try {
                await this.updatePortRole(portName, newRole);
                
                // 更新本地数据
                const port = this.ports.find(p => p.Name === portName);
                if (port) {
                    port.Role = newRole;
                }

                // 重新渲染
                this.renderPorts();
                this.updateStats();
                
                this.closeModal();
                this.showSuccess(`端口 ${portName} 角色已更新为 ${newRole}`);
            } catch (error) {
                console.error('Error updating port role:', error);
                this.showError('更新端口角色失败: ' + error.message);
            }
        });

        // 模态框关闭
        window.addEventListener('click', (e) => {
            const modal = document.getElementById('port-config-modal');
            if (e.target === modal) {
                this.closeModal();
            }
        });
    }

    // 关闭模态框
    closeModal() {
        document.getElementById('port-config-modal').style.display = 'none';
    }

    // 显示加载状态
    showLoading(show) {
        const loading = document.getElementById('loading');
        loading.style.display = show ? 'flex' : 'none';
    }

    // 显示成功消息
    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    // 显示错误消息
    showError(message) {
        this.showNotification(message, 'error');
    }

    // 显示通知
    showNotification(message, type) {
        // 创建通知元素
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <span>${message}</span>
            <button onclick="this.parentElement.remove()">&times;</button>
        `;

        // 添加样式
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 12px 20px;
            border-radius: 4px;
            color: white;
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: space-between;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            background: ${type === 'success' ? '#27ae60' : '#e74c3c'};
        `;

        notification.querySelector('button').style.cssText = `
            background: none;
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            margin-left: 10px;
        `;

        document.body.appendChild(notification);

        // 3秒后自动移除
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 3000);
    }
}

// 全局函数
function refreshPorts() {
    portManager.loadPorts();
}

function exportConfig() {
    const config = {
        timestamp: new Date().toISOString(),
        ports: portManager.ports.map(port => ({
            name: port.Name,
            role: port.Role,
            ip: port.IPAddress,
            netmask: port.Netmask,
            gateway: port.Gateway
        }))
    };

    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `port-config-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function closeModal() {
    portManager.closeModal();
}

// 初始化端口管理器
let portManager;
document.addEventListener('DOMContentLoaded', async () => {
    // 等待认证管理器初始化完成
    if (window.authManager) {
        await window.authManager.initPageAuth();
        portManager = new PortManager();
    }
});

// 添加CSS样式
const style = document.createElement('style');
style.textContent = `
.btn-sm {
    padding: 4px 8px;
    font-size: 12px;
}

.notification {
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}
`;
document.head.appendChild(style);