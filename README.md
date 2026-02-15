# Ultimate MSF Toolkit

终极版 Metasploit Framework 辅助工具集 v2.0.0

一个功能强大、模块化的 Metasploit Framework 辅助工具，提供 Payload 生成、网络扫描、漏洞利用、报告生成等全套渗透测试功能。

## ✨ 主要特性

### 🎯 核心功能
- **Payload 生成**: 支持所有 MSF payload，提供高级编码、模板注入等功能
- **模块管理**: 自动获取和缓存 MSF 模块，支持智能搜索和过滤
- **目标管理**: 完整的目标数据库，记录扫描历史和漏洞信息
- **网络扫描**: 多线程端口扫描、服务检测、漏洞扫描
- **枚举工具**: SMB、SNMP、DNS 等协议枚举
- **报告生成**: 自动生成 HTML、JSON、Markdown、Text 格式报告

### 🚀 高级特性
- **跨平台支持**: 自动适配 Windows、Linux、macOS
- **智能安装**: 自动检测和引导安装 Metasploit Framework
- **代理支持**: 内置代理配置，支持无外网环境
- **数据缓存**: SQLite 数据库缓存，提升性能
- **权限检查**: 自动检测并提示所需权限
- **模块化设计**: 清晰的代码结构，易于扩展

## 📋 系统要求

### 必需
- Python 3.6+
- Metasploit Framework
- SQLite3

### 可选(用于增强功能)
- nmap (高级扫描)
- masscan (快速扫描)
- Root/管理员权限 (某些功能需要)

## 🔧 安装

### 1. 克隆项目
```bash
git clone https://github.com/ADA-XiaoYao/msfvenom.git
cd ultimate-msf-toolkit
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 安装 Metasploit Framework

#### Kali Linux / Parrot OS
```bash
# 通常已预装，更新即可
sudo apt update
sudo apt install metasploit-framework
```

#### Ubuntu / Debian
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

#### macOS
```bash
brew install metasploit
```

#### Windows
从官方下载安装器: https://windows.metasploit.com/

### 4. (可选) 安装扫描工具
```bash
# Debian/Ubuntu
sudo apt install nmap masscan

# macOS
brew install nmap masscan

# Windows (使用 Chocolatey)
choco install nmap
```

## 🎮 使用方法

### 交互式模式 (推荐)
```bash
python main.py
# 或
python main.py -i
```

### 命令行模式

#### 显示版本
```bash
python main.py -v
```

#### 更新所有模块
```bash
python main.py -u
```

#### 显示统计信息
```bash
python main.py -s
```

#### 清除缓存
```bash
python main.py --clear-cache
```

#### 完整渗透测试
```bash
python main.py -t <目标IP>
# 例如
python main.py -t 192.168.1.100
```

## 📖 功能说明

### 1. Payload 生成

#### 快速生成
选择平台 → 输入 LHOST/LPORT → 自动生成常用 payload

#### 高级生成
- 自定义 payload 类型
- 选择编码器和迭代次数
- 设置坏字符
- 使用模板注入
- 生成 handler 脚本

#### 示例
```bash
# 在交互模式中
主菜单 → 1. Payload 生成 → 1. 快速生成
平台: windows
LHOST: 192.168.1.10
LPORT: 4444
```

### 2. 模块管理

- **更新模块**: 从 MSF 获取最新模块列表
- **搜索模块**: 按关键词、类型、平台搜索
- **查看信息**: 详细的模块描述、选项、参考
- **缓存管理**: 智能缓存，减少重复查询

### 3. 目标管理

- **添加目标**: 记录 IP、主机名、OS、服务等信息
- **扫描历史**: 保存所有扫描结果
- **漏洞追踪**: 记录发现的漏洞
- **导入导出**: JSON 格式批量管理

### 4. 扫描工具

#### 端口扫描
```python
# 多线程 TCP 扫描
端口范围: 1-1000
线程数: 10 (可调整)
```

#### 服务检测
自动识别常见服务:
- HTTP/HTTPS
- SSH
- FTP
- SMB
- MySQL/MSSQL/PostgreSQL
- 等等...

#### 漏洞扫描
三种扫描类型:
- **基础扫描**: 常见漏洞 (MS17-010、弱口令等)
- **Web扫描**: Web应用漏洞
- **网络扫描**: 网络服务漏洞

#### OS 检测
使用 nmap 进行操作系统指纹识别

#### 协议枚举
- **SMB**: 共享、用户、SID 枚举
- **SNMP**: 系统信息枚举
- **DNS**: 域名信息收集

### 5. 报告生成

支持多种格式:
- **HTML**: 美观的可视化报告
- **JSON**: 结构化数据，易于解析
- **Text**: 纯文本，便于查看
- **Markdown**: 文档格式，便于编辑

自动包含:
- 扫描时间和元数据
- 目标信息
- 开放端口列表
- 服务检测结果
- 漏洞扫描结果
- OS 检测信息

### 6. 完整渗透测试

一键执行完整流程:
1. 端口扫描 (1-1000)
2. 服务检测
3. 漏洞扫描
4. OS 检测
5. 自动枚举 (如发现相应服务)
6. 生成 HTML + JSON 报告

## 🗂️ 项目结构

```
ultimate_msf_toolkit/
├── main.py                 # 主程序入口
├── config.py               # 配置和系统检查
├── database.py             # 数据库管理
├── msf_manager.py          # MSF 模块管理器
├── payload_generator.py    # Payload 生成器
├── scanner.py              # 扫描器模块
├── report_generator.py     # 报告生成器
├── requirements.txt        # Python 依赖
├── README.md              # 项目说明
└── .msf_cache/            # 缓存目录 (自动创建)
    └── msf_modules.db     # SQLite 数据库
```

## ⚙️ 配置

### 缓存配置
```python
# 在 config.py 中修改
CACHE_DIR = Path(".msf_cache")  # 缓存目录
CACHE_TTL = 7200                # 缓存有效期(秒)
```

### 代理配置
```bash
# 在程序中
主菜单 → 7. 设置 → 1. 代理设置
```

### Metasploit 路径
程序会自动搜索以下路径:
- `/usr/share/metasploit-framework`
- `/opt/metasploit-framework`
- `/usr/local/share/metasploit-framework`
- `C:\metasploit-framework` (Windows)
- 等等...

## 🔒 安全提示

1. **仅用于授权测试**: 只在获得明确授权的系统上使用
2. **遵守法律法规**: 未经授权的渗透测试可能违法
3. **保护敏感信息**: 报告中可能包含敏感信息，妥善保管
4. **权限管理**: 某些功能需要 root 权限，按需使用
5. **网络隔离**: 建议在隔离环境中进行测试

## 🐛 故障排除

### Metasploit 未找到
```bash
# 检查安装
which msfconsole
which msfvenom

# 手动设置路径 (在 config.py 中)
MSF_POSSIBLE_PATHS.append("/your/custom/path")
```

### 数据库错误
```bash
# 清除缓存
python main.py --clear-cache

# 或删除缓存目录
rm -rf .msf_cache
```

### 扫描超时
```python
# 在 scanner.py 中调整超时时间
timeout=60  # 修改为更大的值
```

### 权限不足
```bash
# Linux/macOS
sudo python main.py

# Windows (以管理员运行)
右键 → 以管理员身份运行
```

## 📝 更新日志

### v2.0.0 (2026-02-15)
- 完全重构，模块化设计
- 新增完整的数据库支持
- 新增目标管理功能
- 改进的报告生成器
- 跨平台支持
- 代理配置支持
- 自动安装向导

### v1.0.0
- 初始版本
- 基础 payload 生成
- 简单扫描功能

## 🤝 贡献

欢迎贡献代码！请遵循以下步骤:

1. Fork 本项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目仅供学习和研究使用。使用本工具进行任何非法活动，后果自负。

## 👥 作者

- **Alfanet**
- GitHub: https://github.com/ADA-XiaoYao/msfvenom

## 🙏 致谢

- Metasploit Framework Team
- 所有贡献者和测试人员
- 开源社区

## 📧 联系方式

- Issues: https://github.com/ADA-XiaoYao/msfvenom/issues
- Email: adaxyao@gmail.com

---

**免责声明**: 本工具仅供安全研究和授权测试使用。未经授权对他人系统进行渗透测试是违法行为。使用本工具产生的任何法律责任由使用者自行承担。

⭐ 如果这个项目对你有帮助，请给个 Star！
