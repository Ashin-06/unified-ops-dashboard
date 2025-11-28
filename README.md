# ✨ Unified Ops Dashboard

A comprehensive real-time monitoring dashboard that aggregates system metrics, security alerts, and infrastructure data from multiple sources into a unified, AI-powered interface.

![Dashboard Version](https://img.shields.io/badge/version-15.24-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🚀 Features

### Core Monitoring
- **Real-time System Metrics**: CPU, memory, disk, and network monitoring
- **Multi-Server Dashboard**: Monitor multiple servers from a single interface
- **Historical Data**: Track performance trends with customizable time ranges
- **Interactive Charts**: Zoomable, pan-able charts with Chart.js

### Security & Infrastructure
- **🔒 Wazuh Integration**: Security event monitoring and analysis
- **🖥️ Zabbix Integration**: Infrastructure monitoring and alerting
- **📊 Grafana Integration**: Advanced visualization and dashboards
- **🛡️ Port Scanner**: Remote security scanning capabilities

### Advanced Features
- **Process Management**: View, sort, and kill processes with tree view
- **Network Connections**: Monitor active connections with detailed metadata
- **Packet Sniffing**: Real-time HTTP/HTTPS request capture (optional)
- **AI Log Analysis**: Intelligent log parsing and insights
- **Multi-Server Comparison**: Side-by-side server metrics comparison
- **Alert System**: Configurable thresholds with cooldown management
- **Dark Mode**: Eye-friendly theme switching

## 📋 Prerequisites

- **Python 3.8+**
- **Windows** (tested on Windows 10/11)
- **Administrator privileges** (required for process management and packet sniffing)

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Ashin-06/unified-ops-dashboard.git
cd unified-ops-dashboard
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the Dashboard

Edit `config.json` to set:
- Master API key
- Alert thresholds
- Integration settings (Wazuh, Zabbix, Grafana)
- Performance tuning parameters

**Example config.json:**
```json
{
  "master_api_key": "YOUR_SECRET_KEY_HERE",
  "performance": {
    "frontend_poll_interval": 15,
    "db_batch_size": 100
  },
  "alerts": {
    "cpu_threshold": 80,
    "memory_threshold": 80,
    "disk_threshold": 90
  }
}
```

### 4. (Optional) Configure Remote Agents

Edit `agent_config.json` to add remote servers:
```json
{
  "agents": [
    {
      "hostname": "server-01",
      "url": "http://192.168.1.100:8082",
      "api_key": "agent_secret_key"
    }
  ]
}
```

## 🎯 Quick Start

### Run the Dashboard

**Option 1: Using the Batch File (Recommended)**
```bash
start_dashboard.bat
```
This automatically requests administrator privileges.

**Option 2: Manual Start**
```bash
python main.py
```

Then open your browser to: **http://localhost:8081**

## 📦 Project Structure

```
ServerMonitor/
├── main.py                 # FastAPI application (master server)
├── monitor.py              # Core monitoring logic
├── database.py             # SQLite database operations
├── agent.py                # Remote agent implementation
├── wazuh_integration.py    # Wazuh API integration
├── zabbix_integration.py   # Zabbix API integration
├── index.html              # Dashboard UI (monolithic)
├── config.json             # Main configuration
├── agent_config.json       # Remote agent configuration
├── start_dashboard.bat     # Windows launcher with admin elevation
├── Data/                   # SQLite database storage
├── Logs/                   # Application logs
├── static/                 # Static assets (CSS/JS if separated)
└── tools/                  # Utility scripts
```

## 🔐 Security Considerations

1. **API Keys**: Change the default `master_api_key` in `config.json`
2. **Network Exposure**: By default, the server binds to `0.0.0.0:8081` - consider firewall rules
3. **Process Management**: The `/api/processes/kill` endpoint should be secured (see `improvements.md`)
4. **HTTPS**: Consider using a reverse proxy (nginx/caddy) for production deployments

## 🌐 API Endpoints

### System Metrics
- `GET /api/stats?hostname=<name>` - Current system stats
- `GET /api/metrics?range=<time>&hostname=<name>` - Historical metrics

### Process Management
- `GET /api/processes?hostname=<name>` - Process list
- `POST /api/processes/kill` - Kill a process

### Integrations
- `GET /api/wazuh/stats` - Wazuh summary
- `GET /api/wazuh/agents` - Wazuh agent list
- `GET /api/zabbix/problems` - Active Zabbix problems

### Agent Operations
- `POST /api/agent/submit` - Agent data submission
- `GET /api/servers` - List all known servers

## 🎨 Dashboard Tabs

1. **📊 Overview**: Real-time charts for CPU, memory, network, disk, and requests
2. **🔒 Wazuh Security**: Security alerts and agent status
3. **🖥️ Zabbix Infra**: Infrastructure monitoring and triggers
4. **📊 Grafana**: Embedded Grafana dashboards (if configured)
5. **🛡️ Port Scanner**: Remote port scanning utility
6. **🌐 Requests**: HTTP/HTTPS request logs (requires packet sniffing)
7. **⚠️ Alerts**: System alerts and warnings
8. **⚙️ Services**: Windows service status
9. **💻 Processes**: Process management (top list & tree view)
10. **🔗 Connections**: Active network connections
11. **📋 Logs**: Application logs with AI analysis
12. **📡 Server Status**: Multi-server health overview
13. **🖥️🖥️ Comparison**: Side-by-side server comparison

## 🤝 Contributing

Contributions are welcome! See `CONTRIBUTING.md` for guidelines.

## 📝 License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## 🐛 Known Issues

- Packet sniffing requires admin privileges and may conflict with antivirus software
- Windows-specific implementation (process management uses `psutil`)
- Large log files can slow down the log viewer

## 🔮 Roadmap

- [ ] Linux/macOS support
- [ ] User authentication system
- [ ] Prometheus exporter
- [ ] Docker containerization
- [ ] Auto-reconnect on server disconnect
- [ ] Log export functionality
- [ ] Mobile-responsive design improvements

## 💡 Tips

- Use **Admin Mode** (`start_dashboard.bat`) for full feature access
- Configure alert thresholds in the Settings tab
- Use the comparison tab to identify performance differences across servers
- Enable dark mode for better visibility in low-light environments

## 📧 Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Made with ❤️ by [Ashin-06](https://github.com/Ashin-06)**
