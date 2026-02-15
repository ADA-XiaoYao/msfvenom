#!/bin/bash

# Ultimate MSF Toolkit 安装脚本
# 支持 Linux 和 macOS

echo "========================================="
echo "Ultimate MSF Toolkit 安装向导"
echo "========================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检测操作系统
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        DISTRO="macos"
    else
        echo -e "${RED}不支持的操作系统: $OSTYPE${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} 检测到系统: $OS ($DISTRO)"
}

# 检查 Python
check_python() {
    echo ""
    echo "[*] 检查 Python..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION 已安装"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version | cut -d' ' -f2)
        echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION 已安装"
        PYTHON_CMD="python"
    else
        echo -e "${RED}✗${NC} Python 未安装"
        echo "请先安装 Python 3.6+"
        exit 1
    fi
    
    # 检查版本
    MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 6 ]); then
        echo -e "${RED}✗${NC} Python 版本过低 (需要 3.6+)"
        exit 1
    fi
}

# 检查 pip
check_pip() {
    echo ""
    echo "[*] 检查 pip..."
    
    if command -v pip3 &> /dev/null; then
        echo -e "${GREEN}✓${NC} pip3 已安装"
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        echo -e "${GREEN}✓${NC} pip 已安装"
        PIP_CMD="pip"
    else
        echo -e "${RED}✗${NC} pip 未安装"
        echo "请先安装 pip"
        exit 1
    fi
}

# 安装 Python 依赖
install_python_deps() {
    echo ""
    echo "[*] 安装 Python 依赖..."
    
    $PIP_CMD install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} Python 依赖安装完成"
    else
        echo -e "${RED}✗${NC} Python 依赖安装失败"
        exit 1
    fi
}

# 检查 Metasploit
check_metasploit() {
    echo ""
    echo "[*] 检查 Metasploit Framework..."
    
    if command -v msfconsole &> /dev/null && command -v msfvenom &> /dev/null; then
        MSF_VERSION=$(msfconsole -v | head -n1)
        echo -e "${GREEN}✓${NC} Metasploit Framework 已安装"
        echo "  版本: $MSF_VERSION"
    else
        echo -e "${YELLOW}⚠${NC} Metasploit Framework 未安装"
        install_metasploit
    fi
}

# 安装 Metasploit
install_metasploit() {
    echo ""
    read -p "是否安装 Metasploit Framework? (y/n): " choice
    
    if [ "$choice" != "y" ]; then
        echo -e "${YELLOW}⚠${NC} 跳过 Metasploit 安装"
        echo "  注意: 程序需要 Metasploit Framework 才能运行"
        return
    fi
    
    echo ""
    echo "[*] 安装 Metasploit Framework..."
    
    if [ "$OS" == "linux" ]; then
        if [ "$DISTRO" == "ubuntu" ] || [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "kali" ]; then
            echo "  使用 APT 安装..."
            sudo apt update
            sudo apt install -y metasploit-framework
        elif [ "$DISTRO" == "fedora" ] || [ "$DISTRO" == "rhel" ] || [ "$DISTRO" == "centos" ]; then
            echo "  使用 DNF 安装..."
            sudo dnf install -y metasploit-framework
        elif [ "$DISTRO" == "arch" ] || [ "$DISTRO" == "manjaro" ]; then
            echo "  使用 AUR 安装..."
            echo "  请手动执行: yay -S metasploit"
        else
            echo -e "${YELLOW}⚠${NC} 未识别的发行版"
            echo "  请访问: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
        fi
    elif [ "$OS" == "macos" ]; then
        if command -v brew &> /dev/null; then
            echo "  使用 Homebrew 安装..."
            brew install metasploit
        else
            echo -e "${RED}✗${NC} Homebrew 未安装"
            echo "  请先安装 Homebrew: https://brew.sh"
        fi
    fi
    
    # 再次检查
    if command -v msfconsole &> /dev/null; then
        echo -e "${GREEN}✓${NC} Metasploit Framework 安装成功"
    else
        echo -e "${RED}✗${NC} Metasploit Framework 安装失败"
    fi
}

# 检查可选工具
check_optional_tools() {
    echo ""
    echo "[*] 检查可选工具..."
    
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}✓${NC} nmap 已安装"
    else
        echo -e "${YELLOW}⚠${NC} nmap 未安装 (可选)"
    fi
    
    if command -v masscan &> /dev/null; then
        echo -e "${GREEN}✓${NC} masscan 已安装"
    else
        echo -e "${YELLOW}⚠${NC} masscan 未安装 (可选)"
    fi
}

# 安装可选工具
install_optional_tools() {
    echo ""
    read -p "是否安装可选扫描工具 (nmap, masscan)? (y/n): " choice
    
    if [ "$choice" != "y" ]; then
        echo -e "${YELLOW}⚠${NC} 跳过可选工具安装"
        return
    fi
    
    echo ""
    echo "[*] 安装可选工具..."
    
    if [ "$OS" == "linux" ]; then
        if [ "$DISTRO" == "ubuntu" ] || [ "$DISTRO" == "debian" ] || [ "$DISTRO" == "kali" ]; then
            sudo apt install -y nmap masscan
        elif [ "$DISTRO" == "fedora" ] || [ "$DISTRO" == "rhel" ] || [ "$DISTRO" == "centos" ]; then
            sudo dnf install -y nmap masscan
        elif [ "$DISTRO" == "arch" ] || [ "$DISTRO" == "manjaro" ]; then
            sudo pacman -S --noconfirm nmap masscan
        fi
    elif [ "$OS" == "macos" ]; then
        if command -v brew &> /dev/null; then
            brew install nmap masscan
        fi
    fi
    
    echo -e "${GREEN}✓${NC} 可选工具安装完成"
}

# 设置权限
setup_permissions() {
    echo ""
    echo "[*] 设置文件权限..."
    
    chmod +x main.py
    chmod +x install.sh
    
    echo -e "${GREEN}✓${NC} 权限设置完成"
}

# 创建快捷方式
create_shortcut() {
    echo ""
    read -p "是否创建系统快捷方式? (y/n): " choice
    
    if [ "$choice" != "y" ]; then
        return
    fi
    
    if [ "$OS" == "linux" ]; then
        INSTALL_DIR=$(pwd)
        echo "#!/bin/bash" > /tmp/ultimate-msf
        echo "cd $INSTALL_DIR" >> /tmp/ultimate-msf
        echo "$PYTHON_CMD main.py \"\$@\"" >> /tmp/ultimate-msf
        chmod +x /tmp/ultimate-msf
        sudo mv /tmp/ultimate-msf /usr/local/bin/ultimate-msf
        echo -e "${GREEN}✓${NC} 快捷方式已创建: ultimate-msf"
    elif [ "$OS" == "macos" ]; then
        INSTALL_DIR=$(pwd)
        echo "#!/bin/bash" > /tmp/ultimate-msf
        echo "cd $INSTALL_DIR" >> /tmp/ultimate-msf
        echo "$PYTHON_CMD main.py \"\$@\"" >> /tmp/ultimate-msf
        chmod +x /tmp/ultimate-msf
        sudo mv /tmp/ultimate-msf /usr/local/bin/ultimate-msf
        echo -e "${GREEN}✓${NC} 快捷方式已创建: ultimate-msf"
    fi
}

# 测试安装
test_installation() {
    echo ""
    echo "[*] 测试安装..."
    
    $PYTHON_CMD main.py --version > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} 安装测试通过"
    else
        echo -e "${RED}✗${NC} 安装测试失败"
    fi
}

# 主函数
main() {
    detect_os
    check_python
    check_pip
    install_python_deps
    check_metasploit
    check_optional_tools
    install_optional_tools
    setup_permissions
    create_shortcut
    test_installation
    
    echo ""
    echo "========================================="
    echo -e "${GREEN}安装完成!${NC}"
    echo "========================================="
    echo ""
    echo "启动方法:"
    echo "  $PYTHON_CMD main.py"
    echo ""
    if command -v ultimate-msf &> /dev/null; then
        echo "或使用快捷方式:"
        echo "  ultimate-msf"
        echo ""
    fi
    echo "查看帮助:"
    echo "  $PYTHON_CMD main.py -h"
    echo ""
    echo "完整渗透测试:"
    echo "  $PYTHON_CMD main.py -t <目标IP>"
    echo ""
    echo "========================================="
}

# 运行主函数
main
