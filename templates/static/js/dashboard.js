// 仪表板页面逻辑

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    checkAuthAndLoadDashboard();
});

// 检查认证状态并加载仪表板
async function checkAuthAndLoadDashboard() {
    const authToken = localStorage.getItem('authToken');
    
    if (!authToken) {
        // 没有token，显示未认证提示
        showUnauthenticated();
        return;
    }
    
    try {
        // 尝试调用需要认证的API来验证token
        const response = await apiRequest('/api/status');
        
        if (response && response.ok) {
            // 认证成功，显示仪表板内容
            showDashboardContent();
            // 加载仪表板数据
            loadDashboardData();
        } else {
            // 认证失败，清除无效token并显示未认证提示
            localStorage.removeItem('authToken');
            showUnauthenticated();
        }
    } catch (error) {
        console.error('认证检查失败:', error);
        // 网络错误或其他问题，显示未认证提示
        localStorage.removeItem('authToken');
        showUnauthenticated();
    }
}

// 显示未认证提示
function showUnauthenticated() {
    document.getElementById('authCheck').style.display = 'none';
    document.getElementById('unauthenticated').style.display = 'block';
    document.getElementById('dashboardContent').style.display = 'none';
}

// 显示仪表板内容
function showDashboardContent() {
    document.getElementById('authCheck').style.display = 'none';
    document.getElementById('unauthenticated').style.display = 'none';
    document.getElementById('dashboardContent').style.display = 'block';
}

// 加载仪表板数据
async function loadDashboardData() {
    try {
        const response = await apiRequest('/api/status');
        if (response && response.ok) {
            const data = await response.json();
            updateDashboardStats(data);
        } else {
            showMessage('加载仪表板数据失败', 'error');
        }
    } catch (error) {
        console.error('加载仪表板数据失败:', error);
        showMessage('加载仪表板数据失败: ' + error.message, 'error');
    }
}

// 更新仪表板统计数据
function updateDashboardStats(data) {
    document.getElementById('interfaceCount').textContent = data.interfaces || 0;
    document.getElementById('routeCount').textContent = data.routes || 0;
    document.getElementById('arpCount').textContent = data.arp_entries || 0;
    document.getElementById('dhcpLeases').textContent = data.dhcp_leases || 0;
}

// 定期刷新数据
setInterval(function() {
    // 只有在显示仪表板内容时才刷新数据
    if (document.getElementById('dashboardContent').style.display !== 'none') {
        loadDashboardData();
    }
}, 30000); // 每30秒刷新一次