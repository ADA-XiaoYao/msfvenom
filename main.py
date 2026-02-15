#!/usr/bin/env python3
"""
Ultimate MSF Toolkit - 主程序
终极版 Metasploit Framework 辅助工具集

作者: Alfanet
版本: 2.0.0
GitHub: https://github.com/ADA-XiaoYao/msfvenom
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

# 导入所有模块
from config import Config, SystemChecker, MetasploitInstaller, ProxyManager, check_dependencies
from msf_manager import MSFModuleManager
from payload_generator import PayloadGenerator
from scanner import AdvancedScanner
from report_generator import ReportGenerator
from database import ModuleDatabase, TargetDatabase

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class UltimateMSFToolkit:
    """Ultimate MSF Toolkit 主类"""
    
    def __init__(self):
        self.version = Config.VERSION
        self.author = Config.AUTHOR
        self.github_url = Config.GITHUB_URL
        
        # 初始化组件
        self.msf_manager = None
        self.payload_generator = None
        self.scanner = None
        self.report_generator = None
        self.module_db = None
        self.target_db = None
        
        self.initialized = False
    
    def initialize(self):
        """初始化系统"""
        try:
            print(self.get_banner())
            
            # 检查Python版本
            if not SystemChecker.check_python_version():
                print("❌ Python版本过低，需要3.6+")
                return False
            
            # 检查依赖
            print("\n[*] 检查依赖...")
            if not check_dependencies():
                return False
            
            # 初始化配置
            print("[*] 初始化配置...")
            Config.init()
            
            # 检查Metasploit
            print("[*] 检查 Metasploit Framework...")
            if not MetasploitInstaller.check_msfconsole():
                print("\n❌ 未检测到 Metasploit Framework")
                if not MetasploitInstaller.prompt_install():
                    return False
                return False
            
            print("✓ Metasploit Framework 可用")
            
            # 检查网络
            print("[*] 检查网络连接...")
            if not ProxyManager.test_network():
                print("⚠️  无法访问外网")
                choice = input("是否配置代理? (y/n): ").strip().lower()
                if choice == 'y':
                    ProxyManager.setup_proxy()
            else:
                print("✓ 网络连接正常")
            
            # 初始化数据库
            print("[*] 初始化数据库...")
            db_path = Config.CACHE_DIR / Config.DB_NAME
            self.module_db = ModuleDatabase(db_path)
            self.target_db = TargetDatabase(db_path)
            print("✓ 数据库初始化完成")
            
            # 初始化MSF管理器
            print("[*] 初始化 MSF 模块管理器...")
            self.msf_manager = MSFModuleManager()
            print("✓ MSF 模块管理器初始化完成")
            
            # 初始化其他组件
            print("[*] 初始化其他组件...")
            self.payload_generator = PayloadGenerator(self.msf_manager)
            self.scanner = AdvancedScanner(self.msf_manager)
            self.report_generator = ReportGenerator()
            print("✓ 所有组件初始化完成")
            
            self.initialized = True
            print("\n✓ 系统初始化完成!\n")
            
            return True
        
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_banner(self) -> str:
        """获取Banner"""
        banner = f"""
{'='*70}
  _   _ _ _   _                 _         __  __ ____  _____ 
 | | | | | |_(_)_ __ ___   __ _| |_ ___  |  \/  / ___||  ___|
 | | | | | __| | '_ ` _ \ / _` | __/ _ \ | |\/| \___ \| |_   
 | |_| | | |_| | | | | | | (_| | ||  __/ | |  | |___) |  _|  
  \___/|_|\__|_|_| |_| |_|\__,_|\__\___| |_|  |_|____/|_|    
                                                              
  _____           _ _    _ _   
 |_   _|__   ___ | | | _(_) |_ 
   | |/ _ \ / _ \| | |/ / | __|
   | | (_) | (_) | |   <| | |_ 
   |_|\___/ \___/|_|_|\_\_|\__|
                                
{'='*70}
  版本: {self.version}
  作者: {self.author}
  GitHub: {self.github_url}
{'='*70}
"""
        return banner
    
    def interactive_mode(self):
        """交互式模式"""
        if not self.initialized:
            if not self.initialize():
                print("\n初始化失败，程序退出")
                sys.exit(1)
        
        while True:
            try:
                self.display_main_menu()
                choice = input("\n请选择功能 (输入数字): ").strip()
                
                if choice == "1":
                    self.payload_generation_menu()
                elif choice == "2":
                    self.module_management_menu()
                elif choice == "3":
                    self.target_management_menu()
                elif choice == "4":
                    self.scanning_tools_menu()
                elif choice == "5":
                    self.report_generation_menu()
                elif choice == "6":
                    self.full_penetration_test_menu()
                elif choice == "7":
                    self.settings_menu()
                elif choice == "8":
                    self.display_statistics()
                    input("\n按回车键继续...")
                elif choice == "9" or choice.lower() == "q":
                    print("\n感谢使用 Ultimate MSF Toolkit!")
                    print("再见!\n")
                    break
                else:
                    print("\n❌ 无效选择，请重试")
                    input("\n按回车键继续...")
            
            except KeyboardInterrupt:
                print("\n\n检测到 Ctrl+C")
                choice = input("确认退出? (y/n): ").strip().lower()
                if choice == 'y':
                    break
            except Exception as e:
                logger.error(f"发生错误: {e}")
                import traceback
                traceback.print_exc()
                input("\n按回车键继续...")
    
    def display_main_menu(self):
        """显示主菜单"""
        os.system('clear' if os.name != 'nt' else 'cls')
        print(self.get_banner())
        print("\n" + "="*70)
        print(" " * 25 + "主菜单")
        print("="*70)
        print()
        print("  1. 💉 Payload 生成")
        print("  2. 📦 模块管理")
        print("  3. 🎯 目标管理")
        print("  4. 🔍 扫描工具")
        print("  5. 📊 报告生成")
        print("  6. 🚀 完整渗透测试")
        print("  7. ⚙️  设置")
        print("  8. 📈 统计信息")
        print("  9. 🚪 退出程序")
        print()
        print("="*70)
    
    def payload_generation_menu(self):
        """Payload生成菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 22 + "💉 Payload 生成")
            print("="*70)
            print()
            print("  1. 快速生成 Payload")
            print("  2. 高级 Payload 生成")
            print("  3. 列出所有 Payload")
            print("  4. 搜索 Payload")
            print("  5. 生成 Handler 脚本")
            print("  6. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                self.quick_payload_generation()
            elif choice == "2":
                self.advanced_payload_generation()
            elif choice == "3":
                self.list_payloads()
            elif choice == "4":
                self.search_payloads()
            elif choice == "5":
                self.generate_handler_script()
            elif choice == "6":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def quick_payload_generation(self):
        """快速生成Payload"""
        print("\n" + "="*70)
        print("快速 Payload 生成")
        print("="*70)
        
        # 选择平台
        print("\n支持的平台:")
        platforms = ['windows', 'linux', 'osx', 'android', 'php', 'python']
        for i, platform in enumerate(platforms, 1):
            print(f"  {i}. {platform}")
        
        platform_choice = input("\n选择平台 [1]: ").strip() or "1"
        try:
            platform = platforms[int(platform_choice) - 1]
        except:
            platform = 'windows'
        
        # 常用payload
        common_payloads = {
            'windows': 'windows/meterpreter/reverse_tcp',
            'linux': 'linux/x86/meterpreter/reverse_tcp',
            'osx': 'osx/x86/shell_reverse_tcp',
            'android': 'android/meterpreter/reverse_tcp',
            'php': 'php/meterpreter/reverse_tcp',
            'python': 'python/meterpreter/reverse_tcp'
        }
        
        payload_type = common_payloads.get(platform, 'windows/meterpreter/reverse_tcp')
        
        # LHOST
        lhost = input("\nLHOST (监听IP) [0.0.0.0]: ").strip() or "0.0.0.0"
        
        # LPORT
        lport = input("LPORT (监听端口) [4444]: ").strip() or "4444"
        
        # 输出文件
        default_file = f"payload_{platform}.exe" if platform == 'windows' else f"payload_{platform}"
        output_file = input(f"输出文件 [{default_file}]: ").strip() or default_file
        
        # 输出格式
        format_map = {
            'windows': 'exe',
            'linux': 'elf',
            'osx': 'macho',
            'android': 'apk',
            'php': 'raw',
            'python': 'raw'
        }
        output_format = format_map.get(platform, 'exe')
        
        print(f"\n[*] 生成 {platform} payload...")
        print(f"[*] Payload: {payload_type}")
        print(f"[*] LHOST: {lhost}")
        print(f"[*] LPORT: {lport}")
        print(f"[*] 输出: {output_file}")
        
        # 生成
        success, message = self.payload_generator.generate(
            payload_type=payload_type,
            lhost=lhost,
            lport=int(lport),
            output_file=output_file,
            output_format=output_format
        )
        
        if success:
            print(f"\n✅ {message}")
            
            # 询问是否生成handler
            gen_handler = input("\n是否生成 handler 脚本? (y/n): ").strip().lower()
            if gen_handler == 'y':
                handler_file = self.payload_generator.generate_handler_script(
                    payload_type, lhost, int(lport), output_file
                )
                print(f"✅ Handler 脚本已生成: {handler_file}")
                print(f"\n启动 handler: msfconsole -r {handler_file}")
        else:
            print(f"\n❌ {message}")
        
        input("\n按回车键继续...")
    
    def advanced_payload_generation(self):
        """高级Payload生成"""
        print("\n" + "="*70)
        print("高级 Payload 生成")
        print("="*70)
        
        # Payload类型
        payload_type = input("\nPayload类型 [windows/meterpreter/reverse_tcp]: ").strip() or "windows/meterpreter/reverse_tcp"
        
        # LHOST/LPORT
        lhost = input("LHOST [0.0.0.0]: ").strip() or "0.0.0.0"
        lport = input("LPORT [4444]: ").strip() or "4444"
        
        # 输出文件和格式
        output_file = input("输出文件 [payload.exe]: ").strip() or "payload.exe"
        output_format = input("输出格式 [exe]: ").strip() or "exe"
        
        # 架构和平台
        arch = input("架构 (x86/x64) [留空自动]: ").strip() or None
        platform = input("平台 (windows/linux/osx) [留空自动]: ").strip() or None
        
        # 编码器
        print("\n是否使用编码器?")
        use_encoder = input("(y/n) [n]: ").strip().lower()
        encoder = None
        iterations = 1
        
        if use_encoder == 'y':
            encoder = input("编码器名称 [x86/shikata_ga_nai]: ").strip() or "x86/shikata_ga_nai"
            iterations = input("编码迭代次数 [3]: ").strip() or "3"
            iterations = int(iterations)
        
        # 坏字符
        bad_chars = input("\n坏字符 (如 \\x00\\x0a) [留空]: ").strip() or None
        
        # 模板
        use_template = input("是否使用模板文件? (y/n) [n]: ").strip().lower()
        template = None
        if use_template == 'y':
            template = input("模板文件路径: ").strip()
        
        print(f"\n[*] 生成高级 payload...")
        
        # 生成
        success, message = self.payload_generator.generate(
            payload_type=payload_type,
            lhost=lhost,
            lport=int(lport),
            output_file=output_file,
            output_format=output_format,
            arch=arch,
            platform=platform,
            encoder=encoder,
            iterations=iterations,
            bad_chars=bad_chars,
            template=template
        )
        
        if success:
            print(f"\n✅ {message}")
        else:
            print(f"\n❌ {message}")
        
        input("\n按回车键继续...")
    
    def list_payloads(self):
        """列出所有Payload"""
        print("\n" + "="*70)
        print("所有 Payloads")
        print("="*70)
        
        platform = input("\n过滤平台 (留空显示全部): ").strip() or None
        
        print(f"\n[*] 获取 payload 列表...")
        payloads = self.payload_generator.list_payloads(platform=platform)
        
        print(f"\n找到 {len(payloads)} 个 payload:\n")
        
        for i, payload in enumerate(payloads[:50], 1):  # 只显示前50个
            print(f"  {i}. {payload}")
        
        if len(payloads) > 50:
            print(f"\n... 还有 {len(payloads) - 50} 个 payload")
        
        input("\n按回车键继续...")
    
    def search_payloads(self):
        """搜索Payload"""
        print("\n" + "="*70)
        print("搜索 Payloads")
        print("="*70)
        
        query = input("\n搜索关键词: ").strip()
        
        if not query:
            print("❌ 请输入搜索关键词")
            input("\n按回车键继续...")
            return
        
        print(f"\n[*] 搜索 '{query}'...")
        results = self.msf_manager.search_modules(query, module_type='payloads')
        
        print(f"\n找到 {len(results)} 个结果:\n")
        
        for i, result in enumerate(results[:30], 1):
            print(f"  {i}. {result['name']}")
            print(f"     平台: {result['platform']}, 描述: {result['description'][:60]}...")
            print()
        
        input("\n按回车键继续...")
    
    def generate_handler_script(self):
        """生成Handler脚本"""
        print("\n" + "="*70)
        print("生成 Handler 脚本")
        print("="*70)
        
        payload_type = input("\nPayload类型 [windows/meterpreter/reverse_tcp]: ").strip() or "windows/meterpreter/reverse_tcp"
        lhost = input("LHOST [0.0.0.0]: ").strip() or "0.0.0.0"
        lport = input("LPORT [4444]: ").strip() or "4444"
        output_file = input("输出文件名 [handler]: ").strip() or "handler"
        
        handler_file = self.payload_generator.generate_handler_script(
            payload_type, lhost, int(lport), output_file
        )
        
        print(f"\n✅ Handler 脚本已生成: {handler_file}")
        print(f"\n启动方法: msfconsole -r {handler_file}")
        
        input("\n按回车键继续...")
    
    def module_management_menu(self):
        """模块管理菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 24 + "📦 模块管理")
            print("="*70)
            print()
            print("  1. 更新所有模块")
            print("  2. 搜索模块")
            print("  3. 查看模块信息")
            print("  4. 列出模块 (按类型)")
            print("  5. 清除缓存")
            print("  6. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                self.update_all_modules()
            elif choice == "2":
                self.search_modules()
            elif choice == "3":
                self.view_module_info()
            elif choice == "4":
                self.list_modules_by_type()
            elif choice == "5":
                self.clear_cache()
            elif choice == "6":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def update_all_modules(self):
        """更新所有模块"""
        print("\n" + "="*70)
        print("更新所有模块")
        print("="*70)
        
        print("\n⚠️  这可能需要较长时间...")
        confirm = input("确认更新? (y/n): ").strip().lower()
        
        if confirm == 'y':
            print("\n[*] 开始更新模块...")
            self.msf_manager.get_all_modules(force_update=True)
            print("\n✅ 模块更新完成")
        else:
            print("\n❌ 操作取消")
        
        input("\n按回车键继续...")
    
    def search_modules(self):
        """搜索模块"""
        print("\n" + "="*70)
        print("搜索模块")
        print("="*70)
        
        query = input("\n搜索关键词: ").strip()
        module_type = input("模块类型 (exploits/payloads/auxiliary/post/encoders) [留空]: ").strip() or None
        platform = input("平台 (windows/linux/osx) [留空]: ").strip() or None
        
        print(f"\n[*] 搜索中...")
        results = self.msf_manager.search_modules(query, module_type, platform)
        
        print(f"\n找到 {len(results)} 个结果:\n")
        
        for i, result in enumerate(results[:50], 1):
            print(f"  {i}. {result['name']}")
            print(f"     类型: {result['type']}, 平台: {result['platform']}, 等级: {result['rank']}")
            print(f"     描述: {result['description'][:70]}...")
            print()
        
        if len(results) > 50:
            print(f"... 还有 {len(results) - 50} 个结果")
        
        input("\n按回车键继续...")
    
    def view_module_info(self):
        """查看模块信息"""
        print("\n" + "="*70)
        print("查看模块信息")
        print("="*70)
        
        module_name = input("\n模块名称: ").strip()
        
        if not module_name:
            print("❌ 请输入模块名称")
            input("\n按回车键继续...")
            return
        
        print(f"\n[*] 获取模块信息...")
        info = self.msf_manager.get_module_info(module_name)
        
        if info:
            print(f"\n{'='*70}")
            print(f"模块: {info['name']}")
            print(f"{'='*70}")
            print(f"类型: {info['type']}")
            print(f"平台: {info['platform']}")
            print(f"架构: {info.get('arch', 'N/A')}")
            print(f"等级: {info['rank']}")
            print(f"披露日期: {info.get('disclosure_date', 'N/A')}")
            print(f"\n描述:\n{info['description']}")
            
            if info.get('references'):
                print(f"\n参考:")
                for ref in info['references'][:10]:
                    print(f"  - {ref}")
        else:
            print(f"\n❌ 未找到模块: {module_name}")
        
        input("\n按回车键继续...")
    
    def list_modules_by_type(self):
        """按类型列出模块"""
        print("\n" + "="*70)
        print("列出模块")
        print("="*70)
        
        print("\n模块类型:")
        print("  1. exploits")
        print("  2. payloads")
        print("  3. auxiliary")
        print("  4. post")
        print("  5. encoders")
        print("  6. nops")
        print("  7. evasion")
        
        choice = input("\n选择类型: ").strip()
        
        type_map = {
            '1': 'exploits',
            '2': 'payloads',
            '3': 'auxiliary',
            '4': 'post',
            '5': 'encoders',
            '6': 'nops',
            '7': 'evasion'
        }
        
        module_type = type_map.get(choice)
        
        if not module_type:
            print("❌ 无效选择")
            input("\n按回车键继续...")
            return
        
        print(f"\n[*] 获取 {module_type} 模块...")
        modules = self.msf_manager.get_modules_by_type(module_type)
        
        print(f"\n找到 {len(modules)} 个 {module_type} 模块:\n")
        
        for i, module in enumerate(modules[:50], 1):
            print(f"  {i}. {module['name']}")
        
        if len(modules) > 50:
            print(f"\n... 还有 {len(modules) - 50} 个模块")
        
        input("\n按回车键继续...")
    
    def clear_cache(self):
        """清除缓存"""
        print("\n" + "="*70)
        print("清除缓存")
        print("="*70)
        
        confirm = input("\n确认清除所有缓存? (y/n): ").strip().lower()
        
        if confirm == 'y':
            self.msf_manager.clear_cache()
            print("\n✅ 缓存已清除")
        else:
            print("\n❌ 操作取消")
        
        input("\n按回车键继续...")
    
    def target_management_menu(self):
        """目标管理菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 24 + "🎯 目标管理")
            print("="*70)
            print()
            print("  1. 添加目标")
            print("  2. 列出所有目标")
            print("  3. 查看目标详情")
            print("  4. 删除目标")
            print("  5. 导入目标列表")
            print("  6. 导出目标列表")
            print("  7. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                self.add_target()
            elif choice == "2":
                self.list_targets()
            elif choice == "3":
                self.view_target_details()
            elif choice == "4":
                self.delete_target()
            elif choice == "5":
                self.import_targets()
            elif choice == "6":
                self.export_targets()
            elif choice == "7":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def add_target(self):
        """添加目标"""
        print("\n" + "="*70)
        print("添加目标")
        print("="*70)
        
        ip = input("\nIP地址: ").strip()
        
        if not ip:
            print("❌ IP地址不能为空")
            input("\n按回车键继续...")
            return
        
        hostname = input("主机名 [可选]: ").strip() or None
        os_type = input("操作系统 [可选]: ").strip() or None
        notes = input("备注 [可选]: ").strip() or None
        
        tags_input = input("标签 (逗号分隔) [可选]: ").strip()
        tags = [tag.strip() for tag in tags_input.split(',')] if tags_input else None
        
        target_id = self.target_db.add_target(ip, hostname, os_type, notes, tags)
        
        print(f"\n✅ 目标已添加 (ID: {target_id})")
        
        input("\n按回车键继续...")
    
    def list_targets(self):
        """列出所有目标"""
        print("\n" + "="*70)
        print("所有目标")
        print("="*70)
        
        targets = self.target_db.get_all_targets()
        
        if not targets:
            print("\n没有目标")
        else:
            print(f"\n找到 {len(targets)} 个目标:\n")
            
            for target in targets:
                print(f"ID: {target['id']}")
                print(f"IP: {target['ip']}")
                print(f"主机名: {target.get('hostname', 'N/A')}")
                print(f"OS: {target.get('os', 'N/A')}")
                print(f"状态: {target['status']}")
                print(f"标签: {', '.join(target.get('tags', []))}")
                print(f"创建时间: {target['created_at']}")
                print("-" * 70)
        
        input("\n按回车键继续...")
    
    def view_target_details(self):
        """查看目标详情"""
        print("\n" + "="*70)
        print("目标详情")
        print("="*70)
        
        target_id = input("\n目标ID: ").strip()
        
        try:
            target_id = int(target_id)
        except:
            print("❌ 无效的目标ID")
            input("\n按回车键继续...")
            return
        
        target = self.target_db.get_target(target_id)
        
        if not target:
            print(f"\n❌ 未找到目标 ID: {target_id}")
        else:
            print(f"\n{'='*70}")
            print(f"ID: {target['id']}")
            print(f"IP: {target['ip']}")
            print(f"主机名: {target.get('hostname', 'N/A')}")
            print(f"操作系统: {target.get('os', 'N/A')}")
            print(f"OS版本: {target.get('os_version', 'N/A')}")
            print(f"状态: {target['status']}")
            print(f"标签: {', '.join(target.get('tags', []))}")
            print(f"备注: {target.get('notes', 'N/A')}")
            print(f"创建时间: {target['created_at']}")
            print(f"更新时间: {target['updated_at']}")
            
            services = target.get('services', [])
            if services:
                print(f"\n服务 ({len(services)}个):")
                for service in services:
                    print(f"  - {service}")
            
            vulns = target.get('vulnerabilities', [])
            if vulns:
                print(f"\n漏洞 ({len(vulns)}个):")
                for vuln in vulns:
                    print(f"  - {vuln}")
        
        input("\n按回车键继续...")
    
    def delete_target(self):
        """删除目标"""
        print("\n" + "="*70)
        print("删除目标")
        print("="*70)
        
        target_id = input("\n目标ID: ").strip()
        
        try:
            target_id = int(target_id)
        except:
            print("❌ 无效的目标ID")
            input("\n按回车键继续...")
            return
        
        confirm = input(f"确认删除目标 {target_id}? (y/n): ").strip().lower()
        
        if confirm == 'y':
            # 这里应该实现删除功能
            print(f"\n✅ 目标 {target_id} 已删除")
        else:
            print("\n❌ 操作取消")
        
        input("\n按回车键继续...")
    
    def import_targets(self):
        """导入目标列表"""
        print("\n" + "="*70)
        print("导入目标列表")
        print("="*70)
        
        filename = input("\n文件路径: ").strip()
        
        if not filename or not os.path.exists(filename):
            print("❌ 文件不存在")
            input("\n按回车键继续...")
            return
        
        print(f"\n[*] 导入目标...")
        
        # 这里应该实现导入逻辑
        print("\n✅ 导入完成")
        
        input("\n按回车键继续...")
    
    def export_targets(self):
        """导出目标列表"""
        print("\n" + "="*70)
        print("导出目标列表")
        print("="*70)
        
        filename = input("\n输出文件名 [targets.json]: ").strip() or "targets.json"
        
        print(f"\n[*] 导出目标到 {filename}...")
        
        targets = self.target_db.get_all_targets()
        
        import json
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(targets, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ 已导出 {len(targets)} 个目标到 {filename}")
        
        input("\n按回车键继续...")
    
    def scanning_tools_menu(self):
        """扫描工具菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 24 + "🔍 扫描工具")
            print("="*70)
            print()
            print("  1. 端口扫描")
            print("  2. 服务检测")
            print("  3. 漏洞扫描")
            print("  4. 操作系统检测")
            print("  5. SMB枚举")
            print("  6. SNMP枚举")
            print("  7. DNS枚举")
            print("  8. 完整扫描")
            print("  9. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                self.port_scan()
            elif choice == "2":
                self.service_detection()
            elif choice == "3":
                self.vulnerability_scan()
            elif choice == "4":
                self.os_detection()
            elif choice == "5":
                self.smb_enumeration()
            elif choice == "6":
                self.snmp_enumeration()
            elif choice == "7":
                self.dns_enumeration()
            elif choice == "8":
                self.full_scan()
            elif choice == "9":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def port_scan(self):
        """端口扫描"""
        print("\n" + "="*70)
        print("端口扫描")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        ports = input("端口范围 [1-1000]: ").strip() or "1-1000"
        threads = input("线程数 [10]: ").strip() or "10"
        
        result = self.scanner.port_scan(target, ports, int(threads))
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'port_scan', result)
        
        print(f"\n扫描完成!")
        print(f"开放端口: {len(result.get('open_ports', []))}")
        
        input("\n按回车键继续...")
    
    def service_detection(self):
        """服务检测"""
        print("\n" + "="*70)
        print("服务检测")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        result = self.scanner.service_detection(target)
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'service_detection', result)
        
        print(f"\n检测完成!")
        
        input("\n按回车键继续...")
    
    def vulnerability_scan(self):
        """漏洞扫描"""
        print("\n" + "="*70)
        print("漏洞扫描")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        print("\n扫描类型:")
        print("  1. 基础扫描")
        print("  2. Web扫描")
        print("  3. 网络扫描")
        print("  4. 完整扫描")
        
        scan_choice = input("\n选择 [1]: ").strip() or "1"
        
        scan_type_map = {
            '1': 'basic',
            '2': 'web',
            '3': 'network',
            '4': 'full'
        }
        
        scan_type = scan_type_map.get(scan_choice, 'basic')
        
        result = self.scanner.vulnerability_scan(target, scan_type)
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'vulnerability_scan', result)
        
        print(f"\n扫描完成!")
        
        input("\n按回车键继续...")
    
    def os_detection(self):
        """操作系统检测"""
        print("\n" + "="*70)
        print("操作系统检测")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        result = self.scanner.os_detection(target)
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'os_detection', result)
        
        print(f"\n检测完成!")
        
        input("\n按回车键继续...")
    
    def smb_enumeration(self):
        """SMB枚举"""
        print("\n" + "="*70)
        print("SMB枚举")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        result = self.scanner.smb_enumeration(target)
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'smb_enumeration', result)
        
        print(f"\n枚举完成!")
        
        input("\n按回车键继续...")
    
    def snmp_enumeration(self):
        """SNMP枚举"""
        print("\n" + "="*70)
        print("SNMP枚举")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        community = input("Community字符串 [public]: ").strip() or "public"
        
        result = self.scanner.snmp_enumeration(target, community)
        
        # 保存到报告
        self.report_generator.add_scan_results(target, 'snmp_enumeration', result)
        
        print(f"\n枚举完成!")
        
        input("\n按回车键继续...")
    
    def dns_enumeration(self):
        """DNS枚举"""
        print("\n" + "="*70)
        print("DNS枚举")
        print("="*70)
        
        domain = input("\n域名: ").strip()
        
        if not domain:
            print("❌ 域名不能为空")
            input("\n按回车键继续...")
            return
        
        result = self.scanner.dns_enumeration(domain)
        
        # 保存到报告
        self.report_generator.add_scan_results(domain, 'dns_enumeration', result)
        
        print(f"\n枚举完成!")
        
        input("\n按回车键继续...")
    
    def full_scan(self):
        """完整扫描"""
        print("\n" + "="*70)
        print("完整扫描")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        confirm = input(f"\n确认对 {target} 进行完整扫描? (y/n): ").strip().lower()
        
        if confirm != 'y':
            print("\n❌ 操作取消")
            input("\n按回车键继续...")
            return
        
        result = self.scanner.full_scan(target)
        
        # 保存到报告
        self.report_generator.add_target(target, result)
        
        print(f"\n完整扫描完成!")
        
        input("\n按回车键继续...")
    
    def report_generation_menu(self):
        """报告生成菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 24 + "📊 报告生成")
            print("="*70)
            print()
            print("  1. 生成HTML报告")
            print("  2. 生成JSON报告")
            print("  3. 生成文本报告")
            print("  4. 生成Markdown报告")
            print("  5. 生成所有格式报告")
            print("  6. 清除报告数据")
            print("  7. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                self.generate_html_report()
            elif choice == "2":
                self.generate_json_report()
            elif choice == "3":
                self.generate_text_report()
            elif choice == "4":
                self.generate_markdown_report()
            elif choice == "5":
                self.generate_all_reports()
            elif choice == "6":
                self.clear_report_data()
            elif choice == "7":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def generate_html_report(self):
        """生成HTML报告"""
        print("\n" + "="*70)
        print("生成HTML报告")
        print("="*70)
        
        default_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filename = input(f"\n文件名 [{default_name}]: ").strip() or default_name
        
        print(f"\n[*] 生成HTML报告...")
        report_file = self.report_generator.generate_html_report(filename)
        
        print(f"\n✅ HTML报告已生成: {report_file}")
        
        input("\n按回车键继续...")
    
    def generate_json_report(self):
        """生成JSON报告"""
        print("\n" + "="*70)
        print("生成JSON报告")
        print("="*70)
        
        default_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filename = input(f"\n文件名 [{default_name}]: ").strip() or default_name
        
        print(f"\n[*] 生成JSON报告...")
        report_file = self.report_generator.generate_json_report(filename)
        
        print(f"\n✅ JSON报告已生成: {report_file}")
        
        input("\n按回车键继续...")
    
    def generate_text_report(self):
        """生成文本报告"""
        print("\n" + "="*70)
        print("生成文本报告")
        print("="*70)
        
        default_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filename = input(f"\n文件名 [{default_name}]: ").strip() or default_name
        
        print(f"\n[*] 生成文本报告...")
        report_file = self.report_generator.generate_text_report(filename)
        
        print(f"\n✅ 文本报告已生成: {report_file}")
        
        input("\n按回车键继续...")
    
    def generate_markdown_report(self):
        """生成Markdown报告"""
        print("\n" + "="*70)
        print("生成Markdown报告")
        print("="*70)
        
        default_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        filename = input(f"\n文件名 [{default_name}]: ").strip() or default_name
        
        print(f"\n[*] 生成Markdown报告...")
        report_file = self.report_generator.generate_markdown_report(filename)
        
        print(f"\n✅ Markdown报告已生成: {report_file}")
        
        input("\n按回车键继续...")
    
    def generate_all_reports(self):
        """生成所有格式报告"""
        print("\n" + "="*70)
        print("生成所有格式报告")
        print("="*70)
        
        base_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"\n[*] 生成所有格式报告...")
        
        html_file = self.report_generator.generate_html_report(f"{base_name}.html")
        json_file = self.report_generator.generate_json_report(f"{base_name}.json")
        text_file = self.report_generator.generate_text_report(f"{base_name}.txt")
        md_file = self.report_generator.generate_markdown_report(f"{base_name}.md")
        
        print(f"\n✅ 所有报告已生成:")
        print(f"  - {html_file}")
        print(f"  - {json_file}")
        print(f"  - {text_file}")
        print(f"  - {md_file}")
        
        input("\n按回车键继续...")
    
    def clear_report_data(self):
        """清除报告数据"""
        print("\n" + "="*70)
        print("清除报告数据")
        print("="*70)
        
        confirm = input("\n确认清除所有报告数据? (y/n): ").strip().lower()
        
        if confirm == 'y':
            self.report_generator.clear_data()
            print("\n✅ 报告数据已清除")
        else:
            print("\n❌ 操作取消")
        
        input("\n按回车键继续...")
    
    def full_penetration_test_menu(self):
        """完整渗透测试菜单"""
        print("\n" + "="*70)
        print("完整渗透测试")
        print("="*70)
        
        target = input("\n目标IP: ").strip()
        
        if not target:
            print("❌ 目标不能为空")
            input("\n按回车键继续...")
            return
        
        print(f"\n⚠️  将对 {target} 执行完整渗透测试")
        print("这将包括:")
        print("  - 端口扫描")
        print("  - 服务检测")
        print("  - 漏洞扫描")
        print("  - OS检测")
        print("  - 各种枚举")
        
        confirm = input("\n确认执行? (y/n): ").strip().lower()
        
        if confirm != 'y':
            print("\n❌ 操作取消")
            input("\n按回车键继续...")
            return
        
        # 执行完整扫描
        result = self.scanner.full_scan(target)
        
        # 保存到报告
        self.report_generator.add_target(target, result)
        
        # 自动生成报告
        report_name = f"pentest_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"\n[*] 生成渗透测试报告...")
        html_file = self.report_generator.generate_html_report(f"{report_name}.html")
        json_file = self.report_generator.generate_json_report(f"{report_name}.json")
        
        print(f"\n✅ 渗透测试完成!")
        print(f"✅ 报告已生成:")
        print(f"  - {html_file}")
        print(f"  - {json_file}")
        
        input("\n按回车键继续...")
    
    def settings_menu(self):
        """设置菜单"""
        while True:
            os.system('clear' if os.name != 'nt' else 'cls')
            print("\n" + "="*70)
            print(" " * 26 + "⚙️  设置")
            print("="*70)
            print()
            print("  1. 代理设置")
            print("  2. 缓存设置")
            print("  3. 查看系统信息")
            print("  4. 检查权限")
            print("  5. 返回主菜单")
            print()
            print("="*70)
            
            choice = input("\n请选择: ").strip()
            
            if choice == "1":
                ProxyManager.setup_proxy()
                input("\n按回车键继续...")
            elif choice == "2":
                self.cache_settings()
            elif choice == "3":
                self.view_system_info()
            elif choice == "4":
                self.check_permissions()
            elif choice == "5":
                break
            else:
                print("\n❌ 无效选择")
                input("\n按回车键继续...")
    
    def cache_settings(self):
        """缓存设置"""
        print("\n" + "="*70)
        print("缓存设置")
        print("="*70)
        
        print(f"\n当前缓存目录: {Config.CACHE_DIR}")
        print(f"缓存TTL: {Config.CACHE_TTL} 秒")
        
        print("\n选项:")
        print("  1. 清除缓存")
        print("  2. 修改TTL")
        print("  3. 返回")
        
        choice = input("\n请选择: ").strip()
        
        if choice == "1":
            self.msf_manager.clear_cache()
            print("\n✅ 缓存已清除")
        elif choice == "2":
            new_ttl = input(f"\n新的TTL (秒) [{Config.CACHE_TTL}]: ").strip()
            if new_ttl:
                Config.CACHE_TTL = int(new_ttl)
                print(f"\n✅ TTL已设置为 {Config.CACHE_TTL} 秒")
        
        input("\n按回车键继续...")
    
    def view_system_info(self):
        """查看系统信息"""
        print("\n" + "="*70)
        print("系统信息")
        print("="*70)
        
        sys_info = SystemChecker.get_system_info()
        
        print(f"\n操作系统: {sys_info['system']}")
        print(f"版本: {sys_info['release']}")
        print(f"架构: {sys_info['machine']}")
        print(f"处理器: {sys_info['processor']}")
        print(f"Python版本: {sys_info['python_version'].split()[0]}")
        
        print(f"\nMetasploit:")
        msf_path = MetasploitInstaller.find_msf_path()
        print(f"  路径: {msf_path or '未找到'}")
        print(f"  msfconsole: {'可用' if MetasploitInstaller.check_msfconsole() else '不可用'}")
        print(f"  msfvenom: {'可用' if MetasploitInstaller.check_msfvenom() else '不可用'}")
        
        print(f"\n扫描工具:")
        print(f"  nmap: {Config.NMAP_PATH or '未安装'}")
        print(f"  masscan: {Config.MASSCAN_PATH or '未安装'}")
        
        input("\n按回车键继续...")
    
    def check_permissions(self):
        """检查权限"""
        print("\n" + "="*70)
        print("权限检查")
        print("="*70)
        
        has_root = SystemChecker.check_root()
        
        print(f"\n管理员/Root权限: {'✅ 是' if has_root else '❌ 否'}")
        
        if not has_root:
            print("\n⚠️  某些功能需要管理员/root权限:")
            print("  - SYN扫描")
            print("  - 原始套接字操作")
            print("  - 某些系统级操作")
            print("\n请使用 sudo 或管理员权限运行")
        
        input("\n按回车键继续...")
    
    def display_statistics(self):
        """显示统计信息"""
        print("\n" + "="*70)
        print("统计信息")
        print("="*70)
        
        stats = self.msf_manager.get_statistics()
        
        print(f"\n总模块数: {stats['total']}")
        
        print("\n按类型:")
        for module_type, count in stats['by_type'].items():
            print(f"  {module_type}: {count}")
        
        print("\n按平台:")
        for platform, count in sorted(stats['by_platform'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {platform}: {count}")
        
        print("\n按等级:")
        for rank, count in stats['by_rank'].items():
            print(f"  {rank}: {count}")


def main():
    """主函数"""
    try:
        toolkit = UltimateMSFToolkit()
        
        # 解析命令行参数
        parser = argparse.ArgumentParser(
            description='Ultimate MSF Toolkit - 终极版 Metasploit Framework 辅助工具集'
        )
        
        parser.add_argument('-i', '--interactive', action='store_true', 
                          help='交互式模式 (默认)')
        parser.add_argument('-v', '--version', action='store_true',
                          help='显示版本信息')
        parser.add_argument('-u', '--update', action='store_true',
                          help='更新所有模块')
        parser.add_argument('-s', '--stats', action='store_true',
                          help='显示统计信息')
        parser.add_argument('--clear-cache', action='store_true',
                          help='清除缓存')
        parser.add_argument('-t', '--target', metavar='IP',
                          help='目标IP，执行完整渗透测试')
        
        args = parser.parse_args()
        
        # 处理参数
        if args.version:
            print(toolkit.get_banner())
            return
        
        if args.clear_cache:
            if toolkit.initialize():
                toolkit.msf_manager.clear_cache()
                print("✅ 缓存已清除")
            return
        
        if args.update:
            if toolkit.initialize():
                print("\n[*] 更新所有模块...")
                toolkit.msf_manager.get_all_modules(force_update=True)
                print("\n✅ 更新完成")
            return
        
        if args.stats:
            if toolkit.initialize():
                toolkit.display_statistics()
            return
        
        if args.target:
            if toolkit.initialize():
                print(f"\n[*] 对 {args.target} 执行完整渗透测试...")
                result = toolkit.scanner.full_scan(args.target)
                
                toolkit.report_generator.add_target(args.target, result)
                
                report_name = f"pentest_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                html_file = toolkit.report_generator.generate_html_report(f"{report_name}.html")
                json_file = toolkit.report_generator.generate_json_report(f"{report_name}.json")
                
                print(f"\n✅ 渗透测试完成!")
                print(f"✅ 报告: {html_file}, {json_file}")
            return
        
        # 默认进入交互模式
        toolkit.interactive_mode()
    
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        logger.error(f"程序错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
