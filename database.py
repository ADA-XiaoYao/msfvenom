#!/usr/bin/env python3
"""
数据库管理模块
处理所有数据库相关操作，包括模块缓存、目标管理、扫描结果存储
"""

import sqlite3
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)


class DatabaseManager:
    """数据库管理器基类"""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """初始化数据库"""
        raise NotImplementedError("子类必须实现此方法")
    
    def get_connection(self):
        """获取数据库连接"""
        return sqlite3.connect(self.db_path)
    
    def execute_query(self, query: str, params: tuple = None, fetch: str = None):
        """执行SQL查询"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            result = None
            if fetch == "one":
                result = cursor.fetchone()
            elif fetch == "all":
                result = cursor.fetchall()
            
            conn.commit()
            conn.close()
            
            return result
        except sqlite3.Error as e:
            logger.error(f"数据库查询错误: {e}")
            return None


class ModuleDatabase(DatabaseManager):
    """MSF模块数据库管理"""
    
    def _init_database(self):
        """初始化模块数据库"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # MSF模块表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS msf_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                platform TEXT,
                arch TEXT,
                description TEXT,
                options TEXT,
                rank TEXT,
                disclosure_date TEXT,
                references TEXT,
                targets TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 缓存元数据表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                value TEXT,
                last_updated TIMESTAMP NOT NULL
            )
        ''')
        
        # 创建索引
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_module_type 
            ON msf_modules(type)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_module_platform 
            ON msf_modules(platform)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_module_name 
            ON msf_modules(name)
        ''')
        
        conn.commit()
        conn.close()
        
        logger.info("模块数据库初始化完成")
    
    def insert_module(self, module: Dict[str, Any]):
        """插入模块"""
        query = '''
            INSERT OR REPLACE INTO msf_modules 
            (name, type, platform, arch, description, options, rank, disclosure_date, references, targets, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (
            module.get('name'),
            module.get('type'),
            module.get('platform'),
            module.get('arch'),
            module.get('description'),
            json.dumps(module.get('options', {})),
            module.get('rank'),
            module.get('disclosure_date'),
            json.dumps(module.get('references', [])),
            json.dumps(module.get('targets', [])),
            datetime.now().isoformat()
        )
        
        self.execute_query(query, params)
    
    def insert_modules_batch(self, modules: List[Dict[str, Any]]):
        """批量插入模块"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            INSERT OR REPLACE INTO msf_modules 
            (name, type, platform, arch, description, options, rank, disclosure_date, references, targets, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params_list = []
        for module in modules:
            params = (
                module.get('name'),
                module.get('type'),
                module.get('platform'),
                module.get('arch'),
                module.get('description'),
                json.dumps(module.get('options', {})),
                module.get('rank'),
                module.get('disclosure_date'),
                json.dumps(module.get('references', [])),
                json.dumps(module.get('targets', [])),
                datetime.now().isoformat()
            )
            params_list.append(params)
        
        cursor.executemany(query, params_list)
        conn.commit()
        conn.close()
        
        logger.info(f"批量插入 {len(modules)} 个模块")
    
    def get_modules_by_type(self, module_type: str) -> List[Dict[str, Any]]:
        """根据类型获取模块"""
        query = '''
            SELECT name, type, platform, arch, description, options, rank, disclosure_date, references, targets
            FROM msf_modules WHERE type = ?
        '''
        
        results = self.execute_query(query, (module_type,), fetch="all")
        
        if not results:
            return []
        
        modules = []
        for row in results:
            modules.append({
                'name': row[0],
                'type': row[1],
                'platform': row[2],
                'arch': row[3],
                'description': row[4],
                'options': json.loads(row[5]) if row[5] else {},
                'rank': row[6],
                'disclosure_date': row[7],
                'references': json.loads(row[8]) if row[8] else [],
                'targets': json.loads(row[9]) if row[9] else []
            })
        
        return modules
    
    def search_modules(self, query: str, module_type: Optional[str] = None, 
                      platform: Optional[str] = None, min_rank: Optional[str] = None) -> List[Dict[str, Any]]:
        """搜索模块"""
        sql = '''
            SELECT name, type, platform, arch, description, options, rank, disclosure_date, references, targets
            FROM msf_modules 
            WHERE (name LIKE ? OR description LIKE ?)
        '''
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
        
        results = self.execute_query(sql, tuple(params), fetch="all")
        
        if not results:
            return []
        
        modules = []
        for row in results:
            modules.append({
                'name': row[0],
                'type': row[1],
                'platform': row[2],
                'arch': row[3],
                'description': row[4],
                'options': json.loads(row[5]) if row[5] else {},
                'rank': row[6],
                'disclosure_date': row[7],
                'references': json.loads(row[8]) if row[8] else [],
                'targets': json.loads(row[9]) if row[9] else []
            })
        
        return modules
    
    def get_module_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """根据名称获取模块"""
        query = '''
            SELECT name, type, platform, arch, description, options, rank, disclosure_date, references, targets
            FROM msf_modules WHERE name = ?
        '''
        
        result = self.execute_query(query, (name,), fetch="one")
        
        if not result:
            return None
        
        return {
            'name': result[0],
            'type': result[1],
            'platform': result[2],
            'arch': result[3],
            'description': result[4],
            'options': json.loads(result[5]) if result[5] else {},
            'rank': result[6],
            'disclosure_date': result[7],
            'references': json.loads(result[8]) if result[8] else [],
            'targets': json.loads(result[9]) if result[9] else []
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 按类型统计
        cursor.execute("SELECT type, COUNT(*) FROM msf_modules GROUP BY type")
        type_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 按平台统计
        cursor.execute("SELECT platform, COUNT(*) FROM msf_modules GROUP BY platform")
        platform_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 按等级统计
        cursor.execute("SELECT rank, COUNT(*) FROM msf_modules GROUP BY rank")
        rank_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # 总数
        cursor.execute("SELECT COUNT(*) FROM msf_modules")
        total = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total': total,
            'by_type': type_stats,
            'by_platform': platform_stats,
            'by_rank': rank_stats
        }
    
    def update_cache_metadata(self, key: str, value: str = "updated"):
        """更新缓存元数据"""
        query = '''
            INSERT OR REPLACE INTO cache_metadata (key, value, last_updated)
            VALUES (?, ?, ?)
        '''
        params = (key, value, datetime.now().isoformat())
        self.execute_query(query, params)
    
    def get_cache_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """获取缓存元数据"""
        query = "SELECT value, last_updated FROM cache_metadata WHERE key = ?"
        result = self.execute_query(query, (key,), fetch="one")
        
        if not result:
            return None
        
        return {
            'value': result[0],
            'last_updated': datetime.fromisoformat(result[1])
        }
    
    def should_update_cache(self, key: str, ttl_seconds: int = 7200) -> bool:
        """检查是否应该更新缓存"""
        metadata = self.get_cache_metadata(key)
        
        if not metadata:
            return True
        
        age = datetime.now() - metadata['last_updated']
        return age.total_seconds() > ttl_seconds
    
    def clear_all_modules(self):
        """清除所有模块"""
        self.execute_query("DELETE FROM msf_modules")
        self.execute_query("DELETE FROM cache_metadata")
        logger.info("所有模块已清除")


class TargetDatabase(DatabaseManager):
    """目标数据库管理"""
    
    def _init_database(self):
        """初始化目标数据库"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # 目标表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                hostname TEXT,
                os TEXT,
                os_version TEXT,
                status TEXT DEFAULT 'active',
                services TEXT DEFAULT '[]',
                vulnerabilities TEXT DEFAULT '[]',
                notes TEXT,
                tags TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 目标组表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                targets TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 扫描结果表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                scan_type TEXT NOT NULL,
                results TEXT,
                success BOOLEAN DEFAULT 0,
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        # 创建索引
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_target_ip ON targets(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_results(target_id)')
        
        conn.commit()
        conn.close()
        
        logger.info("目标数据库初始化完成")
    
    def add_target(self, ip: str, hostname: str = None, os: str = None, 
                   notes: str = None, tags: List[str] = None) -> int:
        """添加目标"""
        query = '''
            INSERT OR REPLACE INTO targets 
            (ip, hostname, os, notes, tags, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        '''
        params = (
            ip,
            hostname,
            os,
            notes,
            json.dumps(tags or []),
            datetime.now().isoformat()
        )
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        target_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"添加目标: {ip}")
        return target_id
    
    def get_target(self, target_id: int) -> Optional[Dict[str, Any]]:
        """获取目标"""
        query = '''
            SELECT id, ip, hostname, os, os_version, status, services, 
                   vulnerabilities, notes, tags, created_at, updated_at
            FROM targets WHERE id = ?
        '''
        
        result = self.execute_query(query, (target_id,), fetch="one")
        
        if not result:
            return None
        
        return {
            'id': result[0],
            'ip': result[1],
            'hostname': result[2],
            'os': result[3],
            'os_version': result[4],
            'status': result[5],
            'services': json.loads(result[6]) if result[6] else [],
            'vulnerabilities': json.loads(result[7]) if result[7] else [],
            'notes': result[8],
            'tags': json.loads(result[9]) if result[9] else [],
            'created_at': result[10],
            'updated_at': result[11]
        }
    
    def get_all_targets(self) -> List[Dict[str, Any]]:
        """获取所有目标"""
        query = '''
            SELECT id, ip, hostname, os, os_version, status, services, 
                   vulnerabilities, notes, tags, created_at, updated_at
            FROM targets ORDER BY updated_at DESC
        '''
        
        results = self.execute_query(query, fetch="all")
        
        if not results:
            return []
        
        targets = []
        for row in results:
            targets.append({
                'id': row[0],
                'ip': row[1],
                'hostname': row[2],
                'os': row[3],
                'os_version': row[4],
                'status': row[5],
                'services': json.loads(row[6]) if row[6] else [],
                'vulnerabilities': json.loads(row[7]) if row[7] else [],
                'notes': row[8],
                'tags': json.loads(row[9]) if row[9] else [],
                'created_at': row[10],
                'updated_at': row[11]
            })
        
        return targets
    
    def update_target_services(self, target_id: int, services: List[Dict[str, Any]]):
        """更新目标服务"""
        query = "UPDATE targets SET services = ?, updated_at = ? WHERE id = ?"
        params = (json.dumps(services), datetime.now().isoformat(), target_id)
        self.execute_query(query, params)
    
    def add_scan_result(self, target_id: int, scan_type: str, results: Dict[str, Any], 
                       success: bool = True, error: str = None) -> int:
        """添加扫描结果"""
        query = '''
            INSERT INTO scan_results (target_id, scan_type, results, success, error)
            VALUES (?, ?, ?, ?, ?)
        '''
        params = (
            target_id,
            scan_type,
            json.dumps(results),
            success,
            error
        )
        
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        result_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return result_id
    
    def get_scan_results(self, target_id: int, scan_type: str = None) -> List[Dict[str, Any]]:
        """获取扫描结果"""
        if scan_type:
            query = '''
                SELECT id, target_id, scan_type, results, success, error, created_at
                FROM scan_results WHERE target_id = ? AND scan_type = ?
                ORDER BY created_at DESC
            '''
            results = self.execute_query(query, (target_id, scan_type), fetch="all")
        else:
            query = '''
                SELECT id, target_id, scan_type, results, success, error, created_at
                FROM scan_results WHERE target_id = ?
                ORDER BY created_at DESC
            '''
            results = self.execute_query(query, (target_id,), fetch="all")
        
        if not results:
            return []
        
        scan_results = []
        for row in results:
            scan_results.append({
                'id': row[0],
                'target_id': row[1],
                'scan_type': row[2],
                'results': json.loads(row[3]) if row[3] else {},
                'success': bool(row[4]),
                'error': row[5],
                'created_at': row[6]
            })
        
        return scan_results


if __name__ == "__main__":
    # 测试数据库
    from config import Config
    Config.init()
    
    db_path = Config.CACHE_DIR / Config.DB_NAME
    module_db = ModuleDatabase(db_path)
    target_db = TargetDatabase(db_path)
    
    print("数据库测试完成")
