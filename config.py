#!/usr/bin/env python3
"""
配置文件和工具类
"""

import os
import sys
import platform
import shutil
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Config:
    """全局配置类"""
    
    # 版本信息
    VERSION = "2.0.0"
    AUTHOR = "Ultimate MSF Team"
    GITHUB_URL = "https://github.com/yourusername/ultimate-msf-toolkit"
    
    # 缓存配置
    CACHE_DIR = Path(".msf_cache")
    CACHE_TTL = 7200  # 2小时
    DB_NAME = "msf_modules.db"
    
    # Metasploit 可能的安装路径
    MSF_POSSIBLE_PATHS = [
        "/usr/share/metasploit-framework",
        "/opt/metasploit-framework",
        "/var/lib/metasploit-framework",
        os.path.expanduser("~/metasploit-framework"),
        "/usr/local/share/metasploit-framework",
        "C:\\metasploit-framework",  # Windows
        "C:\\Program Files\\Metasploit",  # Windows
    ]
    
    # 代理配置
    PROXY_ENABLED = False
    PROXY_HOST = "127.0.0.1"
    PROXY_PORT = 7890
    
    # 扫描工具路径
    NMAP_PATH = None
    MASSCAN_PATH = None
    
    @classmethod
    def init(cls):
        """初始化配置"""
        cls.CACHE_DIR.mkdir(exist_ok=True)
        logger.info(f"缓存目录已创建: {cls.CACHE_DIR.absolute()}")
        
        # 检测系统工具
        cls.detect_tools()
    
    @classmethod
    def detect_tools(cls):
        """检测系统中的扫描工具"""
        cls.NMAP_PATH = shutil.which("nmap")
        cls.MASSCAN_PATH = shutil.which("masscan")
        
        if cls.NMAP_PATH:
            logger.info(f"检测到 nmap: {cls.NMAP_PATH}")
        else:
            logger.warning("未检测到 nmap，某些功能可能受限")
        
        if cls.MASSCAN_PATH:
            logger.info(f"检测到 masscan: {cls.MASSCAN_PATH}")
        else:
            logger.warning("未检测到 masscan，某些功能可能受限")
    
    @classmethod
    def get_proxy_dict(cls):
        """获取代理配置字典"""
        if cls.PROXY_ENABLED:
            proxy_url = f"http://{cls.PROXY_HOST}:{cls.PROXY_PORT}"
            return {
                "http": proxy_url,
                "https": proxy_url
            }
        return None


class SystemChecker:
    """系统检查类"""
    
    @staticmethod
    def check_root():
        """检查是否有root权限"""
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def require_root(message="此功能需要管理员/root权限"):
        """要求root权限"""
        if not SystemChecker.check_root():
            print(f"\n⚠️  {message}")
            print("请使用 sudo 或管理员权限运行此程序")
            return False
        return True
    
    @staticmethod
    def get_system_info():
        """获取系统信息"""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version
        }
    
    @staticmethod
    def check_python_version():
        """检查Python版本"""
        if sys.version_info < (3, 6):
            logger.error("需要 Python 3.6 或更高版本")
            return False
        return True


class MetasploitInstaller:
    """Metasploit 安装器"""
    
    @staticmethod
    def find_msf_path():
        """查找Metasploit安装路径"""
        for path in Config.MSF_POSSIBLE_PATHS:
            if os.path.exists(path):
                logger.info(f"找到 Metasploit: {path}")
                return path
        return None
    
    @staticmethod
    def check_msfconsole():
        """检查msfconsole是否可用"""
        return shutil.which("msfconsole") is not None
    
    @staticmethod
    def check_msfvenom():
        """检查msfvenom是否可用"""
        return shutil.which("msfvenom") is not None
    
    @staticmethod
    def install_metasploit():
        """安装Metasploit Framework"""
        system = platform.system()
        
        print("\n" + "=" * 60)
        print("Metasploit Framework 安装向导")
        print("=" * 60)
        
        if system == "Linux":
            return MetasploitInstaller._install_linux()
        elif system == "Darwin":
            return MetasploitInstaller._install_macos()
        elif system == "Windows":
            return MetasploitInstaller._install_windows()
        else:
            logger.error(f"不支持的操作系统: {system}")
            return False
    
    @staticmethod
    def _install_linux():
        """Linux系统安装"""
        print("\n检测到 Linux 系统")
        
        # 检测发行版
        try:
            with open("/etc/os-release", "r") as f:
                os_info = f.read().lower()
        except:
            os_info = ""
        
        if "ubuntu" in os_info or "debian" in os_info:
            print("\n检测到 Debian/Ubuntu 系统")
            print("将使用 APT 安装 Metasploit Framework...")
            
            commands = [
                "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall",
                "chmod 755 msfinstall",
                "./msfinstall"
            ]
            
            print("\n请在终端中执行以下命令:")
            for cmd in commands:
                print(f"  {cmd}")
            
        elif "kali" in os_info:
            print("\n检测到 Kali Linux")
            print("Kali 通常预装了 Metasploit，尝试更新...")
            print("执行: sudo apt update && sudo apt install metasploit-framework")
            
        elif "arch" in os_info:
            print("\n检测到 Arch Linux")
            print("执行: yay -S metasploit 或从 AUR 安装")
            
        elif "fedora" in os_info or "rhel" in os_info or "centos" in os_info:
            print("\n检测到 Red Hat 系列系统")
            print("执行: sudo dnf install metasploit-framework")
        
        else:
            print("\n未识别的 Linux 发行版")
            print("请访问: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
        
        return False
    
    @staticmethod
    def _install_macos():
        """macOS系统安装"""
        print("\n检测到 macOS 系统")
        print("\n推荐使用 Homebrew 安装:")
        print("  brew install metasploit")
        print("\n或访问: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
        return False
    
    @staticmethod
    def _install_windows():
        """Windows系统安装"""
        print("\n检测到 Windows 系统")
        print("\n请从官方网站下载安装器:")
        print("  https://windows.metasploit.com/")
        print("\n或使用 Chocolatey:")
        print("  choco install metasploit")
        return False
    
    @staticmethod
    def prompt_install():
        """提示用户安装Metasploit"""
        print("\n" + "!" * 60)
        print("未检测到 Metasploit Framework!")
        print("!" * 60)
        
        choice = input("\n是否要查看安装说明? (y/n): ").strip().lower()
        if choice == 'y':
            MetasploitInstaller.install_metasploit()
            print("\n安装完成后，请重新运行此程序。")
            return False
        else:
            print("\n程序需要 Metasploit Framework 才能运行。")
            return False


class ProxyManager:
    """代理管理器"""
    
    @staticmethod
    def setup_proxy():
        """设置代理"""
        print("\n" + "=" * 60)
        print("代理设置")
        print("=" * 60)
        
        print("\n当前网络状态:")
        if ProxyManager.test_network():
            print("✓ 可以直接访问外网")
            choice = input("\n是否仍要配置代理? (y/n): ").strip().lower()
            if choice != 'y':
                return
        else:
            print("✗ 无法访问外网，需要配置代理")
        
        print("\n支持的代理类型:")
        print("1. HTTP/HTTPS 代理")
        print("2. SOCKS5 代理")
        
        proxy_type = input("\n选择代理类型 [1]: ").strip() or "1"
        
        host = input("代理服务器地址 [127.0.0.1]: ").strip() or "127.0.0.1"
        port = input("代理服务器端口 [7890]: ").strip() or "7890"
        
        Config.PROXY_ENABLED = True
        Config.PROXY_HOST = host
        Config.PROXY_PORT = int(port)
        
        print(f"\n✓ 代理已设置: {host}:{port}")
        
        # 测试代理
        if ProxyManager.test_proxy():
            print("✓ 代理连接成功")
        else:
            print("✗ 代理连接失败，请检查配置")
            Config.PROXY_ENABLED = False
    
    @staticmethod
    def test_network(timeout=3):
        """测试网络连接"""
        import socket
        try:
            socket.create_connection(("www.google.com", 80), timeout=timeout)
            return True
        except:
            try:
                socket.create_connection(("www.baidu.com", 80), timeout=timeout)
                return True
            except:
                return False
    
    @staticmethod
    def test_proxy():
        """测试代理连接"""
        import requests
        try:
            proxies = Config.get_proxy_dict()
            response = requests.get("https://www.google.com", proxies=proxies, timeout=5)
            return response.status_code == 200
        except:
            return False


def check_dependencies():
    """检查依赖项"""
    print("\n检查依赖项...")
    
    required_modules = [
        "requests", "readline", "sqlite3", "argparse"
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError:
            print(f"✗ {module} - 缺失")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n缺少依赖项: {', '.join(missing_modules)}")
        print("请执行: pip install -r requirements.txt")
        return False
    
    print("\n✓ 所有依赖项已满足")
    return True


if __name__ == "__main__":
    # 测试配置
    Config.init()
    SystemChecker.check_python_version()
    check_dependencies()
