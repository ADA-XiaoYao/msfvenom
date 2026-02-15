#!/usr/bin/env python3
"""
报告生成器
生成HTML、JSON、Text、Markdown等格式的渗透测试报告
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        self.report_data = {}
    
    def add_target(self, target: str, data: Dict[str, Any]):
        """添加目标数据"""
        self.report_data[target] = data
    
    def add_scan_results(self, target: str, scan_type: str, results: Dict[str, Any]):
        """添加扫描结果"""
        if target not in self.report_data:
            self.report_data[target] = {}
        
        self.report_data[target][scan_type] = results
    
    def generate_html_report(self, output_file: str) -> str:
        """生成HTML报告"""
        logger.info(f"生成HTML报告: {output_file}")
        
        html_content = self._generate_html_content()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML报告已生成: {output_file}")
        return output_file
    
    def _generate_html_content(self) -> str:
        """生成HTML内容"""
        # HTML头部
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>渗透测试报告 - Ultimate MSF Toolkit</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .metadata {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .metadata-item {
            display: inline-block;
            margin-right: 30px;
            margin-bottom: 10px;
        }
        
        .metadata-label {
            font-weight: bold;
            color: #667eea;
        }
        
        .content {
            padding: 40px;
        }
        
        .target-section {
            margin-bottom: 40px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .target-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            font-size: 1.5em;
            font-weight: bold;
        }
        
        .target-content {
            padding: 20px;
        }
        
        .scan-section {
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
            padding-left: 20px;
        }
        
        .scan-section h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        
        .result-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .result-table th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .result-table td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .result-table tr:hover {
            background: #f8f9fa;
        }
        
        .status-success {
            color: #28a745;
            font-weight: bold;
        }
        
        .status-failure {
            color: #dc3545;
            font-weight: bold;
        }
        
        .status-warning {
            color: #ffc107;
            font-weight: bold;
        }
        
        .code-block {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            margin-right: 8px;
        }
        
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-info {
            background: #d1ecf1;
            color: #0c5460;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 2px solid #e9ecef;
        }
        
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        
        .port-item {
            background: #667eea;
            color: white;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ 渗透测试报告</h1>
            <p>Ultimate MSF Toolkit v2.0</p>
        </div>
        
        <div class="metadata">
            <div class="metadata-item">
                <span class="metadata-label">生成时间:</span> """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
            </div>
            <div class="metadata-item">
                <span class="metadata-label">目标数量:</span> """ + str(len(self.report_data)) + """
            </div>
            <div class="metadata-item">
                <span class="metadata-label">工具版本:</span> v2.0.0
            </div>
        </div>
        
        <div class="content">
"""
        
        # 添加每个目标的内容
        for target, data in self.report_data.items():
            html += self._generate_target_section(target, data)
        
        # HTML尾部
        html += """
        </div>
        
        <div class="footer">
            <p>报告由 <strong>Ultimate MSF Toolkit</strong> 自动生成</p>
            <p>© 2024 Ultimate MSF Team. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_target_section(self, target: str, data: Dict[str, Any]) -> str:
        """生成目标部分的HTML"""
        html = f"""
        <div class="target-section">
            <div class="target-header">
                🎯 目标: {target}
            </div>
            <div class="target-content">
"""
        
        # 端口扫描结果
        if 'port_scan' in data:
            port_data = data['port_scan']
            open_ports = port_data.get('open_ports', [])
            
            html += """
                <div class="scan-section">
                    <h3>📡 端口扫描</h3>
                    <p><span class="badge badge-info">开放端口: """ + str(len(open_ports)) + """</span></p>
                    <div class="port-list">
"""
            for port in open_ports:
                html += f'                        <div class="port-item">{port}</div>\n'
            
            html += """
                    </div>
                </div>
"""
        
        # 服务检测结果
        if 'service_detection' in data:
            services = data['service_detection'].get('services', {})
            
            html += """
                <div class="scan-section">
                    <h3>🔍 服务检测</h3>
                    <table class="result-table">
                        <tr>
                            <th>服务</th>
                            <th>状态</th>
                            <th>详情</th>
                        </tr>
"""
            for service_name, service_info in services.items():
                status = '✅ 检测到' if service_info.get('detected') else '❌ 未检测到'
                status_class = 'status-success' if service_info.get('detected') else 'status-failure'
                output = service_info.get('output', '')[:100]
                
                html += f"""
                        <tr>
                            <td><strong>{service_name}</strong></td>
                            <td class="{status_class}">{status}</td>
                            <td>{output}...</td>
                        </tr>
"""
            
            html += """
                    </table>
                </div>
"""
        
        # 漏洞扫描结果
        if 'vulnerability_scan' in data:
            vuln_results = data['vulnerability_scan'].get('results', {})
            
            html += """
                <div class="scan-section">
                    <h3>⚠️ 漏洞扫描</h3>
                    <table class="result-table">
                        <tr>
                            <th>模块</th>
                            <th>状态</th>
                            <th>漏洞</th>
                        </tr>
"""
            for module, result in vuln_results.items():
                success = result.get('success', False)
                vulnerable = result.get('vulnerable', False)
                
                status_badge = '<span class="badge badge-success">成功</span>' if success else '<span class="badge badge-danger">失败</span>'
                vuln_badge = '<span class="badge badge-danger">存在漏洞</span>' if vulnerable else '<span class="badge badge-success">安全</span>'
                
                html += f"""
                        <tr>
                            <td><strong>{module.split('/')[-1]}</strong></td>
                            <td>{status_badge}</td>
                            <td>{vuln_badge}</td>
                        </tr>
"""
            
            html += """
                    </table>
                </div>
"""
        
        # OS检测结果
        if 'os_detection' in data:
            os_info = data['os_detection']
            if os_info.get('success'):
                html += """
                <div class="scan-section">
                    <h3>💻 操作系统检测</h3>
                    <div class="code-block">
"""
                html += os_info.get('output', '')[:500]
                html += """
                    </div>
                </div>
"""
        
        html += """
            </div>
        </div>
"""
        
        return html
    
    def generate_json_report(self, output_file: str) -> str:
        """生成JSON报告"""
        logger.info(f"生成JSON报告: {output_file}")
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'Ultimate MSF Toolkit',
                'version': 'v2.0.0',
                'targets_count': len(self.report_data)
            },
            'targets': self.report_data
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON报告已生成: {output_file}")
        return output_file
    
    def generate_text_report(self, output_file: str) -> str:
        """生成文本报告"""
        logger.info(f"生成文本报告: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 25 + "渗透测试报告\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"生成工具: Ultimate MSF Toolkit v2.0.0\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"目标数量: {len(self.report_data)}\n")
            f.write("\n" + "=" * 80 + "\n\n")
            
            for target, data in self.report_data.items():
                f.write(f"\n目标: {target}\n")
                f.write("-" * 80 + "\n\n")
                
                # 端口扫描
                if 'port_scan' in data:
                    port_data = data['port_scan']
                    open_ports = port_data.get('open_ports', [])
                    f.write(f"[端口扫描]\n")
                    f.write(f"  开放端口数: {len(open_ports)}\n")
                    f.write(f"  开放端口: {', '.join(map(str, open_ports))}\n\n")
                
                # 服务检测
                if 'service_detection' in data:
                    services = data['service_detection'].get('services', {})
                    f.write(f"[服务检测]\n")
                    for service_name, service_info in services.items():
                        status = "检测到" if service_info.get('detected') else "未检测到"
                        f.write(f"  {service_name}: {status}\n")
                    f.write("\n")
                
                # 漏洞扫描
                if 'vulnerability_scan' in data:
                    vuln_results = data['vulnerability_scan'].get('results', {})
                    f.write(f"[漏洞扫描]\n")
                    for module, result in vuln_results.items():
                        vulnerable = "存在漏洞" if result.get('vulnerable') else "安全"
                        f.write(f"  {module.split('/')[-1]}: {vulnerable}\n")
                    f.write("\n")
                
                f.write("\n")
        
        logger.info(f"文本报告已生成: {output_file}")
        return output_file
    
    def generate_markdown_report(self, output_file: str) -> str:
        """生成Markdown报告"""
        logger.info(f"生成Markdown报告: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# 渗透测试报告\n\n")
            f.write("**Ultimate MSF Toolkit v2.0.0**\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**目标数量**: {len(self.report_data)}\n\n")
            f.write("---\n\n")
            
            for target, data in self.report_data.items():
                f.write(f"## 🎯 目标: {target}\n\n")
                
                # 端口扫描
                if 'port_scan' in data:
                    port_data = data['port_scan']
                    open_ports = port_data.get('open_ports', [])
                    f.write(f"### 📡 端口扫描\n\n")
                    f.write(f"- **开放端口数**: {len(open_ports)}\n")
                    f.write(f"- **开放端口**: {', '.join(map(str, open_ports))}\n\n")
                
                # 服务检测
                if 'service_detection' in data:
                    services = data['service_detection'].get('services', {})
                    f.write(f"### 🔍 服务检测\n\n")
                    f.write("| 服务 | 状态 |\n")
                    f.write("|------|------|\n")
                    for service_name, service_info in services.items():
                        status = "✅ 检测到" if service_info.get('detected') else "❌ 未检测到"
                        f.write(f"| {service_name} | {status} |\n")
                    f.write("\n")
                
                # 漏洞扫描
                if 'vulnerability_scan' in data:
                    vuln_results = data['vulnerability_scan'].get('results', {})
                    f.write(f"### ⚠️ 漏洞扫描\n\n")
                    f.write("| 模块 | 状态 | 漏洞 |\n")
                    f.write("|------|------|------|\n")
                    for module, result in vuln_results.items():
                        success = "✅" if result.get('success') else "❌"
                        vulnerable = "⚠️ 存在漏洞" if result.get('vulnerable') else "✅ 安全"
                        f.write(f"| {module.split('/')[-1]} | {success} | {vulnerable} |\n")
                    f.write("\n")
                
                f.write("---\n\n")
        
        logger.info(f"Markdown报告已生成: {output_file}")
        return output_file
    
    def clear_data(self):
        """清除所有报告数据"""
        self.report_data = {}


if __name__ == "__main__":
    # 测试报告生成器
    generator = ReportGenerator()
    
    # 添加测试数据
    test_data = {
        'port_scan': {
            'open_ports': [21, 22, 80, 443, 3306],
            'total_scanned': 1000
        },
        'service_detection': {
            'services': {
                'ssh': {'detected': True, 'output': 'OpenSSH 7.4'},
                'http': {'detected': True, 'output': 'Apache 2.4'}
            }
        }
    }
    
    generator.add_target('192.168.1.100', test_data)
    
    # 生成报告
    generator.generate_html_report('test_report.html')
    generator.generate_json_report('test_report.json')
    generator.generate_text_report('test_report.txt')
    generator.generate_markdown_report('test_report.md')
    
    print("测试报告已生成")
