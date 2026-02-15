#!/usr/bin/env python3
"""
高级扫描器模块
提供端口扫描、服务检测、漏洞扫描等功能
"""

import subprocess
import socket
import struct
import logging
import threading
import queue
from typing import List, Dict, Optional, Any
from datetime import datetime

from config import Config, SystemChecker
from msf_manager import retry_on_failure

logger = logging.getLogger(__name__)


class PortScanner:
    """端口扫描器"""
    
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
    
    def scan_tcp(self, target: str, ports: str = "1-1000", threads: int = 10, timeout: int = 1) -> Dict[str, Any]:
        """TCP端口扫描"""
        print(f"\n[*] 开始TCP扫描: {target}")
        print(f"[*] 端口范围: {ports}")
        print(f"[*] 线程数: {threads}")
        
        self.open_ports = []
        self.closed_ports = []
        
        # 解析端口范围
        port_list = self._parse_port_range(ports)
        
        # 创建队列
        port_queue = queue.Queue()
        for port in port_list:
            port_queue.put(port)
        
        # 创建线程
        threads_list = []
        for _ in range(threads):
            t = threading.Thread(target=self._tcp_scan_worker, args=(target, port_queue, timeout))
            t.daemon = True
            t.start()
            threads_list.append(t)
        
        # 等待完成
        port_queue.join()
        
        result = {
            'target': target,
            'scan_type': 'tcp',
            'open_ports': sorted(self.open_ports),
            'total_scanned': len(port_list),
            'open_count': len(self.open_ports),
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\n[+] 扫描完成!")
        print(f"[+] 开放端口: {len(self.open_ports)}")
        
        return result
    
    def _tcp_scan_worker(self, target: str, port_queue: queue.Queue, timeout: int):
        """TCP扫描工作线程"""
        while not port_queue.empty():
            try:
                port = port_queue.get()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    self.open_ports.append(port)
                    print(f"[+] 端口 {port} 开放")
                
                sock.close()
                
            except socket.gaierror:
                logger.error(f"无法解析主机: {target}")
                break
            except socket.error as e:
                logger.debug(f"端口 {port} 扫描错误: {e}")
            except Exception as e:
                logger.error(f"扫描异常: {e}")
            finally:
                port_queue.task_done()
    
    def scan_syn(self, target: str, ports: str = "1-1000") -> Dict[str, Any]:
        """SYN扫描（需要root权限）"""
        if not SystemChecker.check_root():
            print("⚠️  SYN扫描需要root权限")
            return {'error': 'Need root privileges'}
        
        # 使用nmap进行SYN扫描
        if Config.NMAP_PATH:
            return self._nmap_syn_scan(target, ports)
        else:
            print("⚠️  未检测到nmap，回退到TCP扫描")
            return self.scan_tcp(target, ports)
    
    def _nmap_syn_scan(self, target: str, ports: str) -> Dict[str, Any]:
        """使用nmap进行SYN扫描"""
        try:
            cmd = ["nmap", "-sS", "-p", ports, "-T4", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
                    port = int(line.split('/')[0])
                    open_ports.append(port)
            
            return {
                'target': target,
                'scan_type': 'syn',
                'open_ports': open_ports,
                'open_count': len(open_ports),
                'raw_output': result.stdout,
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout'}
        except Exception as e:
            logger.error(f"SYN扫描失败: {e}")
            return {'error': str(e)}
    
    def _parse_port_range(self, ports: str) -> List[int]:
        """解析端口范围"""
        port_list = []
        
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        
        return port_list


class ServiceDetector:
    """服务检测器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
    
    def detect_services(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """检测服务"""
        print(f"\n[*] 开始服务检测: {target}")
        
        services = {}
        
        # 常见服务模块
        service_modules = {
            'http': 'auxiliary/scanner/http/http_version',
            'https': 'auxiliary/scanner/http/http_version',
            'ssh': 'auxiliary/scanner/ssh/ssh_version',
            'ftp': 'auxiliary/scanner/ftp/ftp_version',
            'smtp': 'auxiliary/scanner/smtp/smtp_version',
            'smb': 'auxiliary/scanner/smb/smb_version',
            'mysql': 'auxiliary/scanner/mysql/mysql_version',
            'mssql': 'auxiliary/scanner/mssql/mssql_ping',
            'postgresql': 'auxiliary/scanner/postgres/postgres_version',
            'telnet': 'auxiliary/scanner/telnet/telnet_version',
            'rdp': 'auxiliary/scanner/rdp/rdp_scanner',
        }
        
        # 端口到服务的映射
        port_service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            1433: 'mssql',
            5432: 'postgresql',
            3389: 'rdp',
        }
        
        if ports:
            # 根据端口检测服务
            for port in ports:
                service_name = port_service_map.get(port, 'unknown')
                if service_name in service_modules:
                    module = service_modules[service_name]
                    result = self._detect_service(target, port, module)
                    services[f"{service_name}:{port}"] = result
        else:
            # 检测所有常见服务
            for service_name, module in service_modules.items():
                result = self._detect_service(target, None, module)
                if result['detected']:
                    services[service_name] = result
        
        return {
            'target': target,
            'services': services,
            'timestamp': datetime.now().isoformat()
        }
    
    @retry_on_failure(max_retries=2, delay=1)
    def _detect_service(self, target: str, port: Optional[int], module: str) -> Dict[str, Any]:
        """检测单个服务"""
        try:
            options = {'RHOSTS': target}
            if port:
                options['RPORT'] = str(port)
            
            # 构建MSF命令
            commands = [f"use {module}"]
            for key, value in options.items():
                commands.append(f"set {key} {value}")
            commands.append("run")
            
            cmd_str = "; ".join(commands)
            full_cmd = ["msfconsole", "-qx", f"{cmd_str}; exit"]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=60)
            
            detected = result.returncode == 0 and result.stdout.strip()
            
            return {
                'detected': detected,
                'output': result.stdout[:500] if detected else '',
                'module': module
            }
        except subprocess.TimeoutExpired:
            return {'detected': False, 'error': 'Timeout'}
        except Exception as e:
            return {'detected': False, 'error': str(e)}


class VulnerabilityScanner:
    """漏洞扫描器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
    
    def scan(self, target: str, scan_type: str = 'basic') -> Dict[str, Any]:
        """漏洞扫描"""
        print(f"\n[*] 开始漏洞扫描: {target}")
        print(f"[*] 扫描类型: {scan_type}")
        
        results = {}
        
        if scan_type == 'basic':
            modules = self._get_basic_scan_modules()
        elif scan_type == 'web':
            modules = self._get_web_scan_modules()
        elif scan_type == 'network':
            modules = self._get_network_scan_modules()
        else:
            modules = self._get_all_scan_modules()
        
        for module_name, description in modules.items():
            print(f"[*] 运行: {description}")
            result = self._run_scan_module(target, module_name)
            results[module_name] = result
        
        return {
            'target': target,
            'scan_type': scan_type,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_basic_scan_modules(self) -> Dict[str, str]:
        """基础扫描模块"""
        return {
            'auxiliary/scanner/smb/smb_ms17_010': 'MS17-010 (EternalBlue)',
            'auxiliary/scanner/ssh/ssh_login': 'SSH弱口令',
            'auxiliary/scanner/ftp/anonymous': 'FTP匿名登录',
            'auxiliary/scanner/http/dir_scanner': 'HTTP目录扫描',
        }
    
    def _get_web_scan_modules(self) -> Dict[str, str]:
        """Web扫描模块"""
        return {
            'auxiliary/scanner/http/http_version': 'HTTP版本检测',
            'auxiliary/scanner/http/robots_txt': 'robots.txt',
            'auxiliary/scanner/http/dir_scanner': '目录扫描',
            'auxiliary/scanner/http/files_dir': '敏感文件',
            'auxiliary/scanner/http/backup_file': '备份文件',
            'auxiliary/scanner/http/apache_mod_cgi_bash_env': 'Shellshock',
        }
    
    def _get_network_scan_modules(self) -> Dict[str, str]:
        """网络扫描模块"""
        return {
            'auxiliary/scanner/smb/smb_version': 'SMB版本',
            'auxiliary/scanner/smb/smb_enumshares': 'SMB共享枚举',
            'auxiliary/scanner/smb/smb_enumusers': 'SMB用户枚举',
            'auxiliary/scanner/snmp/snmp_enum': 'SNMP枚举',
            'auxiliary/scanner/ssh/ssh_version': 'SSH版本',
        }
    
    def _get_all_scan_modules(self) -> Dict[str, str]:
        """所有扫描模块"""
        all_modules = {}
        all_modules.update(self._get_basic_scan_modules())
        all_modules.update(self._get_web_scan_modules())
        all_modules.update(self._get_network_scan_modules())
        return all_modules
    
    @retry_on_failure(max_retries=2, delay=1)
    def _run_scan_module(self, target: str, module: str) -> Dict[str, Any]:
        """运行扫描模块"""
        try:
            commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                "set VERBOSE false",
                "run"
            ]
            
            cmd_str = "; ".join(commands)
            full_cmd = ["msfconsole", "-qx", f"{cmd_str}; exit"]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            success = result.returncode == 0
            vulnerable = self._check_vulnerability(result.stdout)
            
            return {
                'success': success,
                'vulnerable': vulnerable,
                'output': result.stdout[:1000],
                'module': module
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _check_vulnerability(self, output: str) -> bool:
        """检查是否存在漏洞"""
        vulnerable_indicators = [
            'vulnerable',
            'exploit',
            'success',
            'pwned',
            'compromised',
            'shell',
            'access granted'
        ]
        
        output_lower = output.lower()
        return any(indicator in output_lower for indicator in vulnerable_indicators)


class SMBEnumerator:
    """SMB枚举器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
    
    def enumerate(self, target: str) -> Dict[str, Any]:
        """SMB枚举"""
        print(f"\n[*] 开始SMB枚举: {target}")
        
        results = {}
        
        # SMB枚举模块
        modules = {
            'version': 'auxiliary/scanner/smb/smb_version',
            'shares': 'auxiliary/scanner/smb/smb_enumshares',
            'users': 'auxiliary/scanner/smb/smb_enumusers',
            'sid': 'auxiliary/scanner/smb/smb_lookupsid',
        }
        
        for enum_type, module in modules.items():
            print(f"[*] 枚举 {enum_type}...")
            result = self._run_enum_module(target, module)
            results[enum_type] = result
        
        return {
            'target': target,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    @retry_on_failure(max_retries=2, delay=1)
    def _run_enum_module(self, target: str, module: str) -> Dict[str, Any]:
        """运行枚举模块"""
        try:
            commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                "run"
            ]
            
            cmd_str = "; ".join(commands)
            full_cmd = ["msfconsole", "-qx", f"{cmd_str}; exit"]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'module': module
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class SNMPEnumerator:
    """SNMP枚举器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
    
    def enumerate(self, target: str, community: str = 'public') -> Dict[str, Any]:
        """SNMP枚举"""
        print(f"\n[*] 开始SNMP枚举: {target}")
        print(f"[*] Community字符串: {community}")
        
        modules = {
            'enum': 'auxiliary/scanner/snmp/snmp_enum',
            'login': 'auxiliary/scanner/snmp/snmp_login',
        }
        
        results = {}
        
        for enum_type, module in modules.items():
            print(f"[*] 枚举 {enum_type}...")
            result = self._run_enum_module(target, module, community)
            results[enum_type] = result
        
        return {
            'target': target,
            'community': community,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    @retry_on_failure(max_retries=2, delay=1)
    def _run_enum_module(self, target: str, module: str, community: str) -> Dict[str, Any]:
        """运行SNMP枚举模块"""
        try:
            commands = [
                f"use {module}",
                f"set RHOSTS {target}",
                f"set COMMUNITY {community}",
                "run"
            ]
            
            cmd_str = "; ".join(commands)
            full_cmd = ["msfconsole", "-qx", f"{cmd_str}; exit"]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'module': module
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class DNSEnumerator:
    """DNS枚举器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
    
    def enumerate(self, domain: str) -> Dict[str, Any]:
        """DNS枚举"""
        print(f"\n[*] 开始DNS枚举: {domain}")
        
        results = {}
        
        # 使用MSF的DNS枚举模块
        module = 'auxiliary/gather/dns_enum'
        result = self._run_dns_enum(domain, module)
        results['msf_enum'] = result
        
        # 尝试使用系统工具
        if Config.NMAP_PATH:
            nmap_result = self._nmap_dns_enum(domain)
            results['nmap_enum'] = nmap_result
        
        return {
            'domain': domain,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    @retry_on_failure(max_retries=2, delay=1)
    def _run_dns_enum(self, domain: str, module: str) -> Dict[str, Any]:
        """运行DNS枚举模块"""
        try:
            commands = [
                f"use {module}",
                f"set DOMAIN {domain}",
                "run"
            ]
            
            cmd_str = "; ".join(commands)
            full_cmd = ["msfconsole", "-qx", f"{cmd_str}; exit"]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=60)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'module': module
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _nmap_dns_enum(self, domain: str) -> Dict[str, Any]:
        """使用nmap进行DNS枚举"""
        try:
            cmd = ["nmap", "-sL", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'tool': 'nmap'
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}


class AdvancedScanner:
    """高级扫描器 - 整合所有扫描功能"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector(msf_manager)
        self.vuln_scanner = VulnerabilityScanner(msf_manager)
        self.smb_enumerator = SMBEnumerator(msf_manager)
        self.snmp_enumerator = SNMPEnumerator(msf_manager)
        self.dns_enumerator = DNSEnumerator(msf_manager)
    
    def port_scan(self, target: str, ports: str = "1-1000", threads: int = 10) -> Dict[str, Any]:
        """端口扫描"""
        return self.port_scanner.scan_tcp(target, ports, threads)
    
    def service_detection(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """服务检测"""
        return self.service_detector.detect_services(target, ports)
    
    def vulnerability_scan(self, target: str, scan_type: str = 'basic') -> Dict[str, Any]:
        """漏洞扫描"""
        return self.vuln_scanner.scan(target, scan_type)
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """操作系统检测"""
        print(f"\n[*] 开始操作系统检测: {target}")
        
        if Config.NMAP_PATH:
            try:
                cmd = ["nmap", "-O", target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                return {
                    'target': target,
                    'success': result.returncode == 0,
                    'output': result.stdout,
                    'timestamp': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'nmap not available'}
    
    def smb_enumeration(self, target: str) -> Dict[str, Any]:
        """SMB枚举"""
        return self.smb_enumerator.enumerate(target)
    
    def snmp_enumeration(self, target: str, community: str = 'public') -> Dict[str, Any]:
        """SNMP枚举"""
        return self.snmp_enumerator.enumerate(target, community)
    
    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """DNS枚举"""
        return self.dns_enumerator.enumerate(domain)
    
    def full_scan(self, target: str) -> Dict[str, Any]:
        """完整扫描"""
        print(f"\n{'='*60}")
        print(f"开始完整扫描: {target}")
        print(f"{'='*60}")
        
        results = {}
        
        # 1. 端口扫描
        print("\n[1/5] 端口扫描...")
        results['port_scan'] = self.port_scan(target, "1-1000", 20)
        
        # 2. 服务检测
        print("\n[2/5] 服务检测...")
        open_ports = results['port_scan'].get('open_ports', [])
        if open_ports:
            results['service_detection'] = self.service_detection(target, open_ports)
        
        # 3. 漏洞扫描
        print("\n[3/5] 漏洞扫描...")
        results['vulnerability_scan'] = self.vulnerability_scan(target, 'basic')
        
        # 4. OS检测
        print("\n[4/5] 操作系统检测...")
        results['os_detection'] = self.os_detection(target)
        
        # 5. SMB枚举
        print("\n[5/5] SMB枚举...")
        if 445 in open_ports or 139 in open_ports:
            results['smb_enumeration'] = self.smb_enumeration(target)
        
        results['target'] = target
        results['timestamp'] = datetime.now().isoformat()
        
        print(f"\n{'='*60}")
        print("扫描完成!")
        print(f"{'='*60}")
        
        return results


if __name__ == "__main__":
    # 测试扫描器
    from config import Config
    from msf_manager import MSFModuleManager
    
    Config.init()
    
    print("测试端口扫描...")
    scanner = PortScanner()
    result = scanner.scan_tcp("127.0.0.1", "1-100", 10)
    print(f"扫描结果: {result}")
