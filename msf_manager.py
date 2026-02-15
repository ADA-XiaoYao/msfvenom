#!/usr/bin/env python3
"""
MSF模块管理器
负责从Metasploit Framework获取和管理模块信息
"""

import subprocess
import re
import logging
import time
from typing import List, Dict, Optional, Any
from functools import wraps
from datetime import datetime

from config import Config, MetasploitInstaller
from database import ModuleDatabase

logger = logging.getLogger(__name__)


def retry_on_failure(max_retries=3, delay=1):
    """重试装饰器"""
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
    """MSF模块管理器"""
    
    def __init__(self):
        self.msf_path = MetasploitInstaller.find_msf_path()
        self.db = ModuleDatabase(Config.CACHE_DIR / Config.DB_NAME)
        
        # 检查MSF是否可用
        if not MetasploitInstaller.check_msfconsole():
            logger.error("msfconsole 不可用")
            if not MetasploitInstaller.prompt_install():
                raise RuntimeError("Metasploit Framework 未安装")
        
        # 模块类型列表
        self.module_types = [
            'exploits',
            'payloads', 
            'auxiliary',
            'post',
            'encoders',
            'nops',
            'evasion'
        ]
    
    def get_all_modules(self, force_update=False) -> Dict[str, List[Dict[str, Any]]]:
        """获取所有模块"""
        all_modules = {}
        
        for module_type in self.module_types:
            print(f"\n正在处理 {module_type} 模块...")
            modules = self.get_modules_by_type(module_type, force_update)
            all_modules[module_type] = modules
            print(f"✓ 获取 {len(modules)} 个 {module_type} 模块")
        
        return all_modules
    
    def get_modules_by_type(self, module_type: str, force_update: bool = False) -> List[Dict[str, Any]]:
        """根据类型获取模块"""
        cache_key = f"last_update_{module_type}"
        
        # 检查是否需要更新缓存
        if not force_update and not self.db.should_update_cache(cache_key, Config.CACHE_TTL):
            logger.info(f"使用缓存的 {module_type} 模块")
            return self.db.get_modules_by_type(module_type)
        
        # 从MSF获取模块
        logger.info(f"从 MSF 获取 {module_type} 模块...")
        modules = self._fetch_modules_from_msf(module_type)
        
        if modules:
            # 保存到数据库
            self.db.insert_modules_batch(modules)
            self.db.update_cache_metadata(cache_key)
            logger.info(f"成功缓存 {len(modules)} 个 {module_type} 模块")
        else:
            logger.warning(f"无法获取 {module_type} 模块，使用缓存")
            modules = self.db.get_modules_by_type(module_type)
        
        return modules
    
    @retry_on_failure(max_retries=3, delay=2)
    def _fetch_modules_from_msf(self, module_type: str) -> List[Dict[str, Any]]:
        """从MSF获取模块列表"""
        try:
            # 根据模块类型构建命令
            if module_type == 'payloads':
                cmd = ["msfvenom", "--list", "payloads"]
            elif module_type == 'encoders':
                cmd = ["msfvenom", "--list", "encoders"]
            elif module_type == 'nops':
                cmd = ["msfvenom", "--list", "nops"]
            elif module_type == 'formats':
                cmd = ["msfvenom", "--list", "formats"]
            else:
                cmd = ["msfconsole", "-qx", f"show {module_type}; exit"]
            
            logger.debug(f"执行命令: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode != 0:
                logger.error(f"获取 {module_type} 模块失败: {result.stderr}")
                return []
            
            # 解析输出
            if module_type in ['payloads', 'encoders', 'nops', 'formats']:
                return self._parse_msfvenom_output(result.stdout, module_type)
            else:
                return self._parse_msfconsole_output(result.stdout, module_type)
        
        except subprocess.TimeoutExpired:
            logger.error(f"获取 {module_type} 模块超时")
            return []
        except Exception as e:
            logger.error(f"获取 {module_type} 模块出错: {e}")
            return []
    
    def _parse_msfvenom_output(self, output: str, module_type: str) -> List[Dict[str, Any]]:
        """解析msfvenom输出"""
        modules = []
        lines = output.split('\n')
        start_parsing = False
        
        for line in lines:
            line = line.strip()
            
            # 跳过标题行
            if 'Name' in line and 'Description' in line:
                start_parsing = True
                continue
            
            if not start_parsing or not line or line.startswith('='):
                continue
            
            # 解析模块行
            # 格式: module_name    description
            parts = line.split(None, 1)
            if len(parts) >= 1 and '/' in parts[0]:
                module_name = parts[0]
                description = parts[1] if len(parts) > 1 else 'No description'
                
                module_info = {
                    'name': module_name,
                    'type': module_type,
                    'platform': self._extract_platform(module_name),
                    'arch': self._extract_arch(module_name),
                    'description': description,
                    'options': {},
                    'rank': 'normal',
                    'disclosure_date': '',
                    'references': [],
                    'targets': []
                }
                
                modules.append(module_info)
        
        return modules
    
    def _parse_msfconsole_output(self, output: str, module_type: str) -> List[Dict[str, Any]]:
        """解析msfconsole输出"""
        modules = []
        lines = output.split('\n')
        start_parsing = False
        
        for line in lines:
            line = line.strip()
            
            # 查找分隔线
            if line.startswith('===') or line.startswith('---'):
                start_parsing = True
                continue
            
            if not start_parsing or not line:
                continue
            
            # 跳过标题行
            if line.startswith('Name') or line.startswith('#'):
                continue
            
            # 解析模块行
            parts = line.split(None, 1)
            if len(parts) >= 1 and '/' in parts[0]:
                module_name = parts[0]
                description = parts[1] if len(parts) > 1 else 'No description'
                
                # 提取等级
                rank = self._extract_rank(line)
                
                # 提取披露日期
                disclosure_date = self._extract_disclosure_date(line)
                
                module_info = {
                    'name': module_name,
                    'type': module_type,
                    'platform': self._extract_platform(module_name),
                    'arch': self._extract_arch(module_name),
                    'description': description,
                    'options': {},
                    'rank': rank,
                    'disclosure_date': disclosure_date,
                    'references': [],
                    'targets': []
                }
                
                modules.append(module_info)
        
        return modules
    
    def _extract_platform(self, module_name: str) -> str:
        """从模块名称提取平台"""
        platforms = {
            'windows': 'windows',
            'linux': 'linux',
            'osx': 'osx',
            'macos': 'osx',
            'unix': 'unix',
            'android': 'android',
            'php': 'php',
            'java': 'java',
            'python': 'python',
            'ruby': 'ruby',
            'nodejs': 'nodejs',
            'net': 'net',
            'solaris': 'solaris',
            'bsd': 'bsd',
            'freebsd': 'bsd',
            'netbsd': 'bsd',
            'openbsd': 'bsd',
            'cisco': 'cisco',
            'ios': 'ios',
            'aix': 'aix',
            'hpux': 'hpux',
        }
        
        module_lower = module_name.lower()
        for key, value in platforms.items():
            if key in module_lower:
                return value
        
        return 'multi'
    
    def _extract_arch(self, module_name: str) -> str:
        """从模块名称提取架构"""
        architectures = {
            'x64': 'x64',
            'x86': 'x86',
            'x86_64': 'x64',
            'amd64': 'x64',
            'arm': 'arm',
            'armle': 'armle',
            'armbe': 'armbe',
            'mips': 'mips',
            'mipsle': 'mipsle',
            'mipsbe': 'mipsbe',
            'ppc': 'ppc',
            'sparc': 'sparc',
        }
        
        module_lower = module_name.lower()
        for key, value in architectures.items():
            if key in module_lower:
                return value
        
        return ''
    
    def _extract_rank(self, line: str) -> str:
        """提取模块等级"""
        ranks = ['excellent', 'great', 'good', 'normal', 'average', 'low', 'manual']
        line_lower = line.lower()
        
        for rank in ranks:
            if rank in line_lower:
                return rank
        
        return 'normal'
    
    def _extract_disclosure_date(self, line: str) -> str:
        """提取披露日期"""
        date_pattern = r'\d{4}-\d{2}-\d{2}'
        match = re.search(date_pattern, line)
        return match.group() if match else ''
    
    @retry_on_failure(max_retries=2, delay=1)
    def get_module_info(self, module_name: str) -> Optional[Dict[str, Any]]:
        """获取模块详细信息"""
        # 先从数据库查询
        module_info = self.db.get_module_by_name(module_name)
        
        if module_info:
            return module_info
        
        # 如果数据库没有，从MSF获取
        try:
            cmd = ["msfconsole", "-qx", f"info {module_name}; exit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return self._parse_module_info(result.stdout, module_name)
        except Exception as e:
            logger.error(f"获取模块信息失败: {e}")
        
        return None
    
    def _parse_module_info(self, output: str, module_name: str) -> Dict[str, Any]:
        """解析模块信息"""
        info = {
            'name': module_name,
            'type': '',
            'platform': '',
            'arch': '',
            'description': '',
            'options': {},
            'rank': 'normal',
            'disclosure_date': '',
            'references': [],
            'targets': []
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # 提取基本信息
            if line.startswith('Name:'):
                info['name'] = line.split(':', 1)[1].strip()
            elif line.startswith('Module:'):
                info['type'] = line.split(':', 1)[1].strip().split('/')[0]
            elif line.startswith('Platform:'):
                info['platform'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('Arch:'):
                info['arch'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('Rank:'):
                info['rank'] = line.split(':', 1)[1].strip().lower()
            elif line.startswith('Disclosed:'):
                info['disclosure_date'] = line.split(':', 1)[1].strip()
            elif line.startswith('Description:'):
                current_section = 'description'
                info['description'] = line.split(':', 1)[1].strip()
            elif line.startswith('References:'):
                current_section = 'references'
            elif line.startswith('Available targets:'):
                current_section = 'targets'
            elif current_section == 'description' and line:
                info['description'] += ' ' + line
            elif current_section == 'references' and line:
                info['references'].append(line)
            elif current_section == 'targets' and line:
                info['targets'].append(line)
        
        return info
    
    def search_modules(self, query: str, module_type: Optional[str] = None,
                      platform: Optional[str] = None, min_rank: Optional[str] = None) -> List[Dict[str, Any]]:
        """搜索模块"""
        return self.db.search_modules(query, module_type, platform, min_rank)
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.db.get_statistics()
    
    def clear_cache(self):
        """清除缓存"""
        self.db.clear_all_modules()
        logger.info("模块缓存已清除")


if __name__ == "__main__":
    # 测试模块管理器
    Config.init()
    
    manager = MSFModuleManager()
    
    print("\n测试获取模块...")
    payloads = manager.get_modules_by_type('payloads')
    print(f"获取到 {len(payloads)} 个 payload")
    
    if payloads:
        print(f"\n示例 payload: {payloads[0]}")
    
    print("\n测试搜索...")
    results = manager.search_modules('windows', module_type='payloads')
    print(f"搜索到 {len(results)} 个 Windows payload")
    
    print("\n统计信息:")
    stats = manager.get_statistics()
    print(f"总模块数: {stats['total']}")
    print(f"按类型: {stats['by_type']}")
