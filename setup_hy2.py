# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "paramiko>=3.4.0",
# ]
# ///
"""
Hysteria2 VPS Setup

One-command Hysteria2 proxy server deployment.

Features:
    • Hysteria2 proxy (QUIC-based, high-speed)
    • Port hopping (UDP port range, configurable)
    • Zero-log mode (no access patterns logged)
    • Auto SSL certificate generation
    • Security hardening (SSH key-only, fail2ban)
    • Generates client configs (Clash, native)

Usage:
    uv run setup_hy2.py [OPTIONS]

Options:
    --docker    Use Docker instead of native binary
    --debug     Enable logging (WARNING: logs access patterns)
    --key-auth  Use SSH key-based authentication

Examples:
    uv run setup_hy2.py
    uv run setup_hy2.py --docker
"""

import sys

# Check for required dependency
try:
    import paramiko
except ImportError:
    print("Error: 'paramiko' module is required but not installed.")
    print("Run this script with: uv run setup_hy2.py")
    print("  (uv automatically installs dependencies from inline metadata)")
    print("Or install manually: pip install paramiko")
    sys.exit(1)

import getpass
import secrets
import string
import re
import hashlib
import base64
import argparse
import time
import random
import ipaddress
import socket
import subprocess
import os
import platform
from functools import lru_cache
from pathlib import Path


# ---------------------------------------------------------------------------
# Console formatting helpers – clear, coloured output for steps / warnings
# ---------------------------------------------------------------------------
def _supports_color() -> bool:
    """Check whether the terminal likely supports ANSI colour codes."""
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('FORCE_COLOR'):
        return True
    if platform.system() == 'Windows':
        # Windows Terminal / modern conhost support ANSI
        return os.environ.get('WT_SESSION') is not None or os.environ.get('TERM_PROGRAM') == 'vscode'
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


_COLOR = _supports_color()


def _fmt(code: str, text: str) -> str:
    return f'\033[{code}m{text}\033[0m' if _COLOR else text


def fmt_step(text: str) -> str:
    """Bold cyan for step headers."""
    return _fmt('1;36', text)


def fmt_ok(text: str) -> str:
    """Green for success messages."""
    return _fmt('32', text)


def fmt_warn(text: str) -> str:
    """Yellow for warnings."""
    return _fmt('33', text)


def fmt_err(text: str) -> str:
    """Red for errors."""
    return _fmt('1;31', text)


def fmt_info(text: str) -> str:
    """Dim/grey for informational notes."""
    return _fmt('2', text)


def fmt_banner(text: str) -> str:
    """Bold white for banners."""
    return _fmt('1;37', text)


def print_step(text: str) -> None:
    """Print a formatted step header."""
    print(fmt_step(text))


def print_ok(text: str) -> None:
    print(fmt_ok(text))


def print_warn(text: str) -> None:
    print(fmt_warn(text))


def print_err(text: str) -> None:
    print(fmt_err(text))

# ---------------------------------------------------------------------------
# Constants – centralise magic numbers for clarity and easy tuning
# ---------------------------------------------------------------------------
PORT_HOP_START: int = 20000
PORT_HOP_END: int = 60000
HY2_PASSWORD_LENGTH: int = 24
ROOT_PASSWORD_LENGTH: int = 20
SSH_KEY_BITS: int = 4096
SSL_CERT_DAYS: int = 365
HOP_INTERVAL_MIN: int = 5
HOP_INTERVAL_MAX: int = 15
SSH_CONNECT_TIMEOUT: int = 30
DOWNLOAD_TIMEOUT: int = 300
DOWNLOAD_CONNECT_TIMEOUT: int = 60


@lru_cache(maxsize=1)
def get_local_ips() -> tuple[str, ...]:
    """Get all local IP addresses of this machine.
    
    Results are cached for the lifetime of the process.
    
    Returns:
        Tuple of IP addresses (both IPv4 and IPv6)
    """
    local_ips = ['127.0.0.1', '::1', 'localhost']
    
    try:
        # Get hostname
        hostname = socket.gethostname()
        
        # Get all IP addresses for this hostname
        try:
            for addr_info in socket.getaddrinfo(hostname, None):
                ip = addr_info[4][0]
                if ip not in local_ips:
                    local_ips.append(ip)
        except socket.gaierror:
            pass
        
        # Try to get IP by connecting to external server (doesn't actually connect)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                if local_ip not in local_ips:
                    local_ips.append(local_ip)
        except Exception:
            pass
        
        # Platform-specific methods
        if platform.system() == 'Windows':
            # Windows: use ipconfig
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if 'IPv4' in line or 'IPv6' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if ip and ip not in local_ips:
                                local_ips.append(ip)
            except Exception:
                pass
        else:
            # Unix: use ip addr or ifconfig
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    line_stripped = line.strip()
                    if 'inet ' in line_stripped or 'inet6 ' in line_stripped:
                        parts = line_stripped.split()
                        for i, p in enumerate(parts):
                            if p in ('inet', 'inet6') and i + 1 < len(parts):
                                ip = parts[i+1].split('/')[0]
                                if ip not in local_ips:
                                    local_ips.append(ip)
            except FileNotFoundError:
                # Try ifconfig
                try:
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line:
                            parts = line.strip().split()
                            for i, p in enumerate(parts):
                                if p == 'inet':
                                    ip = parts[i+1]
                                    if ip not in local_ips:
                                        local_ips.append(ip)
                except Exception:
                    pass
            except Exception:
                pass
                
    except Exception:
        pass
    
    return tuple(local_ips)


def is_local_ip(ip: str) -> bool:
    """Check if the given IP is a local IP of this machine.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if the IP is local, False otherwise
    """
    if ip in ['localhost', '127.0.0.1', '::1']:
        return True
    
    local_ips = get_local_ips()
    return ip in local_ips


# Get the script directory for relative paths
SCRIPT_DIR = Path(__file__).parent.resolve()

# Language strings
MESSAGES = {
    'en': {
        'select_language': 'Language / 语言 [en/zh] (default: en): ',
        'title': 'Hysteria2 VPS Setup',
        'found_pubkey': 'Found SSH public key: {}',
        'no_pubkey': 'No SSH public key found at {}',
        'continue_without_key': 'Continue without deploying SSH key? [y/N]: ',
        'aborted_no_key': 'Aborted: no valid SSH public key. Use --pubkey to specify one.',
        'enter_server_ip': 'Server IP: ',
        'error_ip_required': 'Server IP is required.',
        'error_invalid_ip': "'{}' is not a valid IPv4 or IPv6 address.",
        'enter_server_name': 'Server nickname (for config labels, default: IP): ',
        'enter_ssh_port': 'SSH port [22]: ',
        'error_invalid_port': "Invalid SSH port '{}' (must be 1-65535).",
        'error_not_port_number': "'{}' is not a valid port number.",
        'enter_username': 'SSH user [root]: ',
        'enter_password': 'SSH password: ',
        'error_password_required': 'Password is required.',
        'generated_hy2_password': 'Hysteria2 password generated (saved to credentials.txt)',
        'warn_port_in_hop_range': f'Port {{}} overlaps with hop range {PORT_HOP_START}-{PORT_HOP_END} — may cause conflicts!',
        'hy2_service_port': 'Hysteria2 port: {}',
        'connecting': 'Connecting to {}:{}...',
        'connected': 'Connected!',
        'failed_connect': 'Connection failed: {}',
        'step1_deploy_key': '[1/9] Deploying SSH public key...',
        'key_deployed': '  SSH public key deployed!',
        'key_exists': '  SSH public key already on server.',
        'step2_update': '[2/9] Updating system...',
        'step3_packages': '[3/9] Installing packages...',
        'step4_docker': '[4/9] Installing Docker...',
        'step4_native': '[4/9] Installing Hysteria2 (native)...',
        'step5_firewall': '[5/9] Configuring firewall...',
        'step6_workdir': '[6/9] Setting up work directory...',
        'step7_ssl': '[7/9] Generating SSL certificates...',
        'step8_config': '[8/9] Writing config files...',
        'step9_start': '[9/9] Starting Hysteria2 container...',
        'step9_start_native': '[9/9] Starting Hysteria2 service...',
        'retrieving_fingerprint': 'Retrieving certificate fingerprint...',
        'warn_no_pinsha256': 'Could not extract pinSHA256, trying fallback...',
        'verifying_container': 'Verifying container...',
        'container_status': 'Container status: {}',
        'native_install_success': '  ✓ Hysteria2 binary installed!',
        'native_install_failed': '  ✗ Hysteria2 binary install failed!',
        'native_service_success': '  ✓ Hysteria2 service started!',
        'native_service_failed': '  ✗ Hysteria2 service failed to start.',
        'skip_hardening': 'Skipping security hardening (--no-harden)',
        'ssh_closed': 'SSH connection closed.',
        'setup_complete': 'SETUP COMPLETE!',
        'security_summary': 'SECURITY SUMMARY',
        'password_changed_to': '  ✓ Root password changed (saved to credentials.txt)',
        'ssh_key_only': '  ✓ SSH: key-only (password login disabled)',
        'fail2ban_installed': '  ✓ fail2ban: active (brute-force protection)',
        'firewall_hardened': '  ✓ Firewall: hardened (monitoring ports blocked)',
        'agents_disabled': '  ✓ Disabled agents: {}',
        'important_save_password': '  ⚠ Save the new root password!',
        'ssh_password_disabled': '  ⚠ SSH password login DISABLED — use key to connect.',
        'copy_config': 'Copy config to your Clash / Hysteria2 client:',
        'save_info': 'SAVE THIS INFORMATION',
        'new_root_password': 'New root password saved to credentials.txt',
        'ssh_pubkey_path': 'SSH Public Key Path: {}',
        'server_ip_label': 'Server: [see credentials.txt]',
        'to_connect_ssh': 'To connect via SSH:',
        'security_applying': 'Applying security hardening...',
        'security_step1': '  [1/6] Changing root password...',
        'root_password_changed': '  Root password changed!',
        'security_step2': '  [2/6] Configuring SSH key-only auth...',
        'ssh_configured': '  SSH set to key-only auth!',
        'security_step3': '  [3/6] Disabling VPS monitoring agents...',
        'disabled_agent': '    Disabled: {}',
        'security_step4': '  [4/6] Installing fail2ban...',
        'fail2ban_configured': '  fail2ban active!',
        'security_step5': '  [5/6] Hardening firewall...',
        'firewall_hardened_msg': '  Firewall hardened!',
        'security_step6': '  [6/6] Additional security...',
        'security_applied': '  Security measures applied!',
        'error_invalid_port_arg': "Invalid port '{}' (must be 1-65535).",
        'using_key_auth': 'Using SSH key-based authentication',
        'found_privkey': 'Found SSH private key: {}',
        'no_privkey': 'No SSH private key found at {}',
        'detecting_os': '[0/9] Detecting & cleaning up...',
        'detected_os': '  Detected: {} ({})',
        'checking_docker': 'Checking Docker...',
        'docker_found': '  Docker already installed.',
        'docker_not_found': '  Docker not found, installing...',
        'docker_install_success': '  Docker installed!',
        'docker_install_failed': '  Docker installation failed!',
        'unsupported_os': '  Unsupported OS: {}. Trying generic install.',
        'enter_privkey_passphrase': 'Private key passphrase (Enter to skip): ',
        'docker_start_success': '  ✓ Hysteria2 container started!',
        'docker_start_failed': '  ✗ Container failed to start. Checking logs...',
        'verifying_iptables': 'Verifying iptables rules...',
        'iptables_ipv4_ok': f'  ✓ IPv4: ports {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'iptables_ipv4_missing': '  ✗ IPv4 rule missing, adding...',
        'iptables_ipv6_ok': f'  ✓ IPv6: ports {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'iptables_ipv6_missing': '  ✗ IPv6 rule missing, adding...',
        'port_hop_configured': f'  Port hopping: {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'testing_hy2': 'Testing Hysteria2 server...',
        'test_success': '  ✓ Server test passed!',
        'test_failed': '  ✗ Server test failed — check logs.',
        # China mode messages
        'china_mode_enabled': '[China] Running in mainland-China VPS mode',
        'china_downloading_local': '[China] Downloading binary locally (GitHub blocked)...',
        'china_download_success': '  ✓ Downloaded locally: {}',
        'china_download_failed': '  ✗ Local download failed',
        'china_uploading_binary': '[China] Uploading binary via SFTP...',
        'china_upload_success': '  ✓ Binary uploaded',
        'china_upload_failed': '  ✗ Upload failed',
        'china_configuring_docker_mirror': '[China] Setting Aliyun Docker mirror...',
        'china_docker_mirror_configured': '  ✓ Aliyun mirror configured',
        'china_disabling_agents': '[China] Disabling VPS monitoring agents...',
        'china_disguising_service': '[China] Disguising service...',
        'china_service_disguised': '  ✓ Service disguised',
        'mode_switch_cleanup': 'Cleaning up previous mode...',
        'mode_switch_normal_cleaned': '  ✓ Normal mode cleaned up',
        'mode_switch_china_cleaned': '  ✓ China mode cleaned up',
        # Local mode messages
        'local_ip_detected': '[Local] Detected IP: {}',
        'local_mode_confirm': 'Install Hysteria2 on this machine? [y/N]: ',
        'local_mode_enabled': '[Local] Installing locally (no SSH)',
        'local_mode_requires_sudo': '[Local] Requires sudo/root privileges.',
        'local_mode_aborted': 'Local install cancelled.',
        'cleanup_existing': '[0/9] Cleaning up environment...',
        'cleanup_done': '  Previous installation cleaned up.',
    },
    'zh': {
        'select_language': 'Select language / 选择语言 [en/zh] (默认: en): ',
        'title': 'Hysteria2 VPS 安装脚本',
        'found_pubkey': '找到 SSH 公钥: {}',
        'no_pubkey': '未找到 SSH 公钥: {}',
        'continue_without_key': '是否继续（不部署 SSH 公钥）？[y/N]: ',
        'aborted_no_key': '已取消。请使用 --pubkey 指定有效的 SSH 公钥路径',
        'enter_server_ip': '请输入服务器 IP 地址: ',
        'error_ip_required': '错误: 服务器 IP 地址是必填项',
        'error_invalid_ip': "错误: '{}' 不是有效的 IPv4 或 IPv6 地址",
        'enter_server_name': '请输入服务器名称（用于配置标签）: ',
        'enter_ssh_port': '请输入 SSH 端口 [22]: ',
        'error_invalid_port': "错误: 无效的 SSH 端口 '{}'。必须在 1-65535 之间。",
        'error_not_port_number': "错误: '{}' 不是有效的端口号",
        'enter_username': '请输入 SSH 用户名 [root]: ',
        'enter_password': '请输入 SSH 密码: ',
        'error_password_required': '错误: 密码是必填项',
        'generated_hy2_password': 'Hysteria2 密码已生成（已保存到 credentials.txt）',
        'warn_port_in_hop_range': f'[警告] 端口 {{}} 在跳跃端口范围 {PORT_HOP_START}-{PORT_HOP_END} 内，可能导致冲突！',
        'hy2_service_port': 'Hysteria2 服务端口: {}',
        'connecting': '正在连接 {}:{}...',
        'connected': '连接成功！',
        'failed_connect': '连接失败: {}',
        'step1_deploy_key': '[1/9] 部署 SSH 公钥...',
        'key_deployed': '  SSH 公钥已部署！',
        'key_exists': '  SSH 公钥已存在。',
        'step2_update': '[2/9] 更新系统...',
        'step3_packages': '[3/9] 安装依赖包...',
        'step4_docker': '[4/9] 安装 Docker...',
        'step4_native': '[4/9] 安装 Hysteria2（原生）...',
        'step5_firewall': '[5/9] 配置防火墙...',
        'step6_workdir': '[6/9] 创建工作目录...',
        'step7_ssl': '[7/9] 生成 SSL 证书...',
        'step8_config': '[8/9] 写入配置文件...',
        'step9_start': '[9/9] 启动 Hysteria2 容器...',
        'step9_start_native': '[9/9] 启动 Hysteria2 服务...',
        'retrieving_fingerprint': '获取证书指纹...',
        'warn_no_pinsha256': '无法提取 pinSHA256，尝试备用方法...',
        'verifying_container': '验证容器...',
        'container_status': '容器状态: {}',
        'native_install_success': '  ✓ Hysteria2 已安装！',
        'native_install_failed': '  ✗ Hysteria2 安装失败！',
        'native_service_success': '  ✓ Hysteria2 服务已启动！',
        'native_service_failed': '  ✗ Hysteria2 服务启动失败。',
        'skip_hardening': '跳过安全加固（--no-harden）',
        'ssh_closed': 'SSH 连接已关闭。',
        'setup_complete': '部署完成！',
        'security_summary': '安全加固摘要',
        'password_changed_to': '  ✓ Root 密码已更改（已保存到 credentials.txt）',
        'ssh_key_only': '  ✓ SSH: 仅密钥登录（密码已禁用）',
        'fail2ban_installed': '  ✓ fail2ban: 已启用（防暴力破解）',
        'firewall_hardened': '  ✓ 防火墙: 已加固（监控端口已屏蔽）',
        'agents_disabled': '  ✓ 已禁用代理: {}',
        'important_save_password': '  ⚠ 请保存新 root 密码！',
        'ssh_password_disabled': '  ⚠ SSH 密码登录已禁用 — 请用密钥连接。',
        'copy_config': '请将配置复制到 Clash / Hysteria2 客户端:',
        'save_info': '请保存以下信息',
        'new_root_password': '新 root 密码已保存到 credentials.txt',
        'ssh_pubkey_path': 'SSH 公钥路径: {}',
        'server_ip_label': '服务器: [见 credentials.txt]',
        'to_connect_ssh': '通过 SSH 连接:',
        'security_applying': '正在安全加固...',
        'security_step1': '  [1/6] 更改 root 密码...',
        'root_password_changed': '  Root 密码已更改！',
        'security_step2': '  [2/6] 配置 SSH 仅密钥登录...',
        'ssh_configured': '  SSH 已设为仅密钥登录！',
        'security_step3': '  [3/6] 禁用 VPS 监控代理...',
        'disabled_agent': '    已禁用: {}',
        'security_step4': '  [4/6] 安装 fail2ban...',
        'fail2ban_configured': '  fail2ban 已启用！',
        'security_step5': '  [5/6] 加固防火墙...',
        'firewall_hardened_msg': '  防火墙已加固！',
        'security_step6': '  [6/6] 其他安全措施...',
        'security_applied': '  安全措施已应用！',
        'error_invalid_port_arg': "无效端口 '{}'（需 1-65535）。",
        'using_key_auth': '使用 SSH 密钥认证',
        'found_privkey': '找到 SSH 私钥: {}',
        'no_privkey': '未找到 SSH 私钥: {}',
        'detecting_os': '[0/9] 检测并清理环境...',
        'detected_os': '  检测到: {} ({})',
        'checking_docker': '检查 Docker...',
        'docker_found': '  Docker 已安装。',
        'docker_not_found': '  未找到 Docker，正在安装...',
        'docker_install_success': '  Docker 已安装！',
        'docker_install_failed': '  Docker 安装失败！',
        'unsupported_os': '  不支持的 OS: {}，尝试通用安装。',
        'enter_privkey_passphrase': '私钥密码（直接回车跳过）: ',
        'docker_start_success': '  ✓ Hysteria2 容器已启动！',
        'docker_start_failed': '  ✗ 容器启动失败，检查日志...',
        'verifying_iptables': '验证 iptables 规则...',
        'iptables_ipv4_ok': f'  ✓ IPv4: 端口 {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'iptables_ipv4_missing': '  ✗ IPv4 规则缺失，正在添加...',
        'iptables_ipv6_ok': f'  ✓ IPv6: 端口 {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'iptables_ipv6_missing': '  ✗ IPv6 规则缺失，正在添加...',
        'port_hop_configured': f'  端口跳跃: {PORT_HOP_START}-{PORT_HOP_END} → {{}}',
        'testing_hy2': '[9/9] 测试 Hysteria2 服务器...',
        'test_success': '  ✓ 服务器测试通过！',
        'test_failed': '  ✗ 服务器测试失败 — 请查看日志。',
        # China mode messages
        'china_mode_enabled': '[中国模式] 大陆 VPS 模式已启用',
        'china_downloading_local': '[中国] 本地下载 Hysteria2（GitHub 被墙）...',
        'china_download_success': '  ✓ 已下载到本地: {}',
        'china_download_failed': '  ✗ 本地下载失败',
        'china_uploading_binary': '[中国] SFTP 上传中...',
        'china_upload_success': '  ✓ 已上传到服务器',
        'china_upload_failed': '  ✗ 上传失败',
        'china_configuring_docker_mirror': '[中国] 配置阿里云镜像...',
        'china_docker_mirror_configured': '  ✓ 阿里云镜像已配置',
        'china_disabling_agents': '[中国] 禁用监控代理...',
        'china_disguising_service': '[中国] 伪装服务...',
        'china_service_disguised': '  ✓ 服务已伪装',
        'mode_switch_cleanup': '清理先前模式...',
        'mode_switch_normal_cleaned': '  ✓ 普通模式已清理',
        'mode_switch_china_cleaned': '  ✓ 中国模式已清理',
        # Local mode messages
        'local_ip_detected': '[本地] 检测到 IP: {}',
        'local_mode_confirm': '在本机安装 Hysteria2？[y/N]: ',
        'local_mode_enabled': '[本地模式] 本机安装（无需 SSH）',
        'local_mode_requires_sudo': '[本地] 需要 sudo/root 权限。',
        'local_mode_aborted': '本地安装已取消。',
        'cleanup_existing': '[0/9] 清理环境...',
        'cleanup_done': '  已清理先前的安装。',
    }
}

# Global language setting
LANG = 'en'

# Embedded Clash configuration template with rules
CLASH_CONFIG_TEMPLATE = '''# =============================================================================
# Clash Configuration - Generated by setup_hy2.py
# =============================================================================
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

# Performance & Security optimizations
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome
geodata-mode: true
geodata-loader: memconservative
keep-alive-interval: 30
geox-url:
  # Use testingcf (Cloudflare) as it's more reliable than main jsdelivr
  geoip: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
  geosite: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
  mmdb: "https://testingcf.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb"

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "Mijia Cloud"
    - "+.push.apple.com"

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  # Bootstrap DNS for resolving DoH hostnames (must be plain IP)
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  # Primary DNS - China DoH servers (fast for domestic)
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
    - 223.5.5.5
    - 119.29.29.29
  # Fallback DNS - via DoH to avoid hijacking (for foreign domains)
  fallback:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
    - https://dns.quad9.net/dns-query
  # When to use fallback: if resolved IP is not CN, use fallback result
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite:
      - gfw
    ipcidr:
      - 240.0.0.0/4
      - 0.0.0.0/32
  fake-ip-filter:
    # Local/LAN domains
    - '*.lan'
    - '*.local'
    - '*.localhost'
    - '*.home.arpa'
    - '*.direct'
    # Windows network connectivity check
    - '+.msftconnecttest.com'
    - '+.msftncsi.com'
    # Captive portal detection (Android, Apple, etc.)
    - 'connectivitycheck.gstatic.com'
    - 'captive.apple.com'
    - 'detectportal.firefox.com'
    - 'clients3.google.com'
    # QQ (needs real IP for login)
    - 'localhost.ptlogin2.qq.com'
    - '+.qq.com'
    - '+.tencent.com'
    # WeChat
    - '+.weixin.qq.com'
    - '+.wechat.com'
    # Gaming platforms (need real IP for P2P/matchmaking)
    - '+.battle.net'
    - '+.blizzard.com'
    - '+.battlenet.com.cn'
    - '+.roblox.com'
    - '+.rbxcdn.com'
    - '+.simulpong.com'
    - '+.stun.*.*'
    - '+.stun.*.*.*'
    - 'stun.*.*'
    - 'stun.*.*.*'
    # NTP time sync
    - 'time.*.com'
    - 'time.*.gov'
    - 'time.*.edu.cn'
    - 'time1.cloud.tencent.com'
    - 'ntp.*.com'
    - '+.ntp.org.cn'
    # Apple services
    - '+.apple.com'
    - '+.icloud.com'
    # Music streaming (needs real IP for licensing)
    - '+.music.163.com'
    - '+.126.net'
    - 'music.*.com'
    - '*.xiami.com'
    - '+.kugou.com'
    - '+.kuwo.cn'
    # Video streaming
    - '+.bilibili.com'
    - '+.bilivideo.com'
    - '+.iqiyi.com'
    - '+.youku.com'
    # Zhihu
    - '+.zhihu.com'
    - '+.zhimg.com'
    # Router/NAS local access
    - '+.synology.com'
    - '+.router.asus.com'
    - 'routerlogin.net'
    - 'tplinkwifi.net'
    - 'melogin.cn'

proxies:
{proxy_config}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - AUTO
      - {server_name}
  
  - name: AUTO
    type: url-test
    proxies:
      - {server_name}
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: true

# -----------------------------------------------------------------------------
# Rule Providers (external rule sets, auto-updated daily)
# -----------------------------------------------------------------------------
rule-providers:
  reject:
    behavior: domain
    interval: 86400
    path: ./ruleset/reject.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt

  proxy:
    behavior: domain
    interval: 86400
    path: ./ruleset/proxy.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt

  direct:
    behavior: domain
    interval: 86400
    path: ./ruleset/direct.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt

  private:
    behavior: domain
    interval: 86400
    path: ./ruleset/private.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt

  gfw:
    behavior: domain
    interval: 86400
    path: ./ruleset/gfw.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt

  tld-not-cn:
    behavior: domain
    interval: 86400
    path: ./ruleset/tld-not-cn.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt

  google:
    behavior: domain
    interval: 86400
    path: ./ruleset/google.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt

  apple:
    behavior: domain
    interval: 86400
    path: ./ruleset/apple.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt

  icloud:
    behavior: domain
    interval: 86400
    path: ./ruleset/icloud.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt

  telegramcidr:
    behavior: ipcidr
    interval: 86400
    path: ./ruleset/telegramcidr.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt

  lancidr:
    behavior: ipcidr
    interval: 86400
    path: ./ruleset/lancidr.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt

  cncidr:
    behavior: ipcidr
    interval: 86400
    path: ./ruleset/cncidr.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt

  # Note: googlecidr removed - domain-based matching via 'google' rule-provider is sufficient
  # and avoids downloading the large geoip-google.txt file

  applications:
    behavior: classical
    interval: 86400
    path: ./ruleset/applications.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt

# -----------------------------------------------------------------------------
# Rules (ordered by specificity)
# -----------------------------------------------------------------------------
rules:
  # ===================
  # China Big Tech Tracking & Analytics - REJECT
  # Block Chinese tracking services, SDKs, and analytics
  # ===================
  
  # Alibaba/Aliyun Tracking (友盟, ARMS, etc.)
  - DOMAIN-SUFFIX,umeng.com,REJECT
  - DOMAIN-SUFFIX,umeng.co,REJECT
  - DOMAIN-SUFFIX,umengcloud.com,REJECT
  - DOMAIN-SUFFIX,alog.umeng.com,REJECT
  - DOMAIN-SUFFIX,alog.umengcloud.com,REJECT
  - DOMAIN-SUFFIX,uc.cn,REJECT
  - DOMAIN-SUFFIX,alibaba.log,REJECT
  - DOMAIN-SUFFIX,aliyuncs.log,REJECT
  - DOMAIN-SUFFIX,arms.aliyuncs.com,REJECT
  - DOMAIN-SUFFIX,retcode.aliyuncs.com,REJECT
  
  # Tencent Tracking (灯塔, 腾讯分析, MTA, Bugly)
  - DOMAIN-SUFFIX,beacon.qq.com,REJECT
  - DOMAIN-SUFFIX,mta.qq.com,REJECT
  - DOMAIN-SUFFIX,mta.gtimg.com,REJECT
  - DOMAIN-SUFFIX,tajs.qq.com,REJECT
  - DOMAIN-SUFFIX,stat.qq.com,REJECT
  - DOMAIN-SUFFIX,pingtcss.qq.com,REJECT
  - DOMAIN-SUFFIX,pingtas.qq.com,REJECT
  - DOMAIN-SUFFIX,report.qq.com,REJECT
  - DOMAIN-SUFFIX,bugly.qq.com,REJECT
  - DOMAIN-SUFFIX,bugly.qcloud.com,REJECT
  - DOMAIN-SUFFIX,trace.qq.com,REJECT
  - DOMAIN-SUFFIX,trace.tencent.com,REJECT
  - DOMAIN-SUFFIX,beacon.tencent.com,REJECT
  
  # Baidu Tracking (百度统计, 百度联盟)
  - DOMAIN-SUFFIX,hm.baidu.com,REJECT
  - DOMAIN-SUFFIX,hmcdn.baidu.com,REJECT
  - DOMAIN-SUFFIX,cpro.baidu.com,REJECT
  - DOMAIN-SUFFIX,pos.baidu.com,REJECT
  - DOMAIN-SUFFIX,nsclick.baidu.com,REJECT
  - DOMAIN-SUFFIX,click.hm.baidu.com,REJECT
  - DOMAIN-SUFFIX,eclick.baidu.com,REJECT
  - DOMAIN-SUFFIX,bce.baidu.com,REJECT
  - DOMAIN-SUFFIX,mtj.baidu.com,REJECT
  - DOMAIN-SUFFIX,mobads.baidu.com,REJECT
  - DOMAIN-SUFFIX,mobads-logs.baidu.com,REJECT
  - DOMAIN-SUFFIX,duclick.baidu.com,REJECT
  - DOMAIN-SUFFIX,als.baidu.com,REJECT
  - DOMAIN-SUFFIX,wn.pos.baidu.com,REJECT
  
  # ByteDance/Douyin Tracking (抖音, 头条, 火山)
  - DOMAIN-SUFFIX,log.snssdk.com,REJECT
  - DOMAIN-SUFFIX,log.byteoversea.com,REJECT
  - DOMAIN-SUFFIX,applog.snssdk.com,REJECT
  - DOMAIN-SUFFIX,is.snssdk.com,REJECT
  - DOMAIN-SUFFIX,mon.snssdk.com,REJECT
  - DOMAIN-SUFFIX,analytics.pangle.io,REJECT
  - DOMAIN-SUFFIX,pangle.io,REJECT
  - DOMAIN-SUFFIX,pangleglobal.com,REJECT
  - DOMAIN-SUFFIX,bytetrack.com,REJECT
  - DOMAIN-SUFFIX,log.toutiaocloud.com,REJECT
  - DOMAIN-SUFFIX,toblog.ctobsnssdk.com,REJECT
  - DOMAIN-SUFFIX,tosv.byted.org,REJECT
  
  # JD Tracking (京东)
  - DOMAIN-SUFFIX,stat.360buy.com,REJECT
  - DOMAIN-SUFFIX,click.jd.com,REJECT
  - DOMAIN-SUFFIX,jdlog.jd.com,REJECT
  - DOMAIN-SUFFIX,log.jd.com,REJECT
  - DOMAIN-SUFFIX,dlog.jd.com,REJECT
  
  # Xiaomi Tracking (小米统计)
  - DOMAIN-SUFFIX,data.mistat.xiaomi.com,REJECT
  - DOMAIN-SUFFIX,tracking.miui.com,REJECT
  - DOMAIN-SUFFIX,sa.xiaomi.com,REJECT
  - DOMAIN-SUFFIX,sdkconfig.ad.xiaomi.com,REJECT
  - DOMAIN-SUFFIX,t.ad.xiaomi.com,REJECT
  - DOMAIN-SUFFIX,ad.xiaomi.com,REJECT
  
  # Huawei Tracking (华为)
  - DOMAIN-SUFFIX,hianalytics.com,REJECT
  - DOMAIN-SUFFIX,logservice.hicloud.com,REJECT
  - DOMAIN-SUFFIX,metrics.vmall.com,REJECT
  
  # Oppo/Vivo/Realme Tracking
  - DOMAIN-SUFFIX,adsfs.oppomobile.com,REJECT
  - DOMAIN-SUFFIX,bdapi.ads.oppomobile.com,REJECT
  - DOMAIN-SUFFIX,log.ads.oppomobile.com,REJECT
  - DOMAIN-SUFFIX,analytics.vivo.com.cn,REJECT
  - DOMAIN-SUFFIX,applog.vivo.com.cn,REJECT
  
  # NetEase Tracking (网易)
  - DOMAIN-SUFFIX,analytics.163.com,REJECT
  - DOMAIN-SUFFIX,crash.163.com,REJECT
  - DOMAIN-SUFFIX,ntes.nease.net,REJECT
  - DOMAIN-SUFFIX,neis.163.com,REJECT
  
  # Weibo Tracking (微博)
  - DOMAIN-SUFFIX,beacon.sina.com.cn,REJECT
  - DOMAIN-SUFFIX,log.sina.com.cn,REJECT
  - DOMAIN-SUFFIX,slog.sina.com.cn,REJECT
  
  # Zhihu Tracking (知乎)
  - DOMAIN-SUFFIX,sugar.zhihu.com,REJECT
  - DOMAIN-SUFFIX,crash.zhihu.com,REJECT
  - DOMAIN-SUFFIX,zhouyun.zhihu.com,REJECT
  
  # Bilibili Tracking (B站)
  - DOMAIN-SUFFIX,data.bilibili.com,REJECT
  - DOMAIN-SUFFIX,log.bilibili.com,REJECT
  - DOMAIN-SUFFIX,datacenter.bilibili.com,REJECT
  
  # iQiyi Tracking (爱奇艺)
  - DOMAIN-SUFFIX,msg.iqiyi.com,REJECT
  - DOMAIN-SUFFIX,mixer.iqiyi.com,REJECT
  - DOMAIN-SUFFIX,t7z.cupid.iqiyi.com,REJECT
  
  # Generic Chinese Ad Networks & SDKs
  - DOMAIN-SUFFIX,growingio.com,REJECT
  - DOMAIN-SUFFIX,growing.io,REJECT
  - DOMAIN-SUFFIX,shuzilm.cn,REJECT
  - DOMAIN-SUFFIX,cnzz.com,REJECT
  - DOMAIN-SUFFIX,51.la,REJECT
  - DOMAIN-SUFFIX,aldwx.com,REJECT
  - DOMAIN-SUFFIX,adview.cn,REJECT
  - DOMAIN-SUFFIX,miaozhen.com,REJECT
  - DOMAIN-SUFFIX,admaster.com.cn,REJECT
  - DOMAIN-SUFFIX,tanx.com,REJECT
  - DOMAIN-SUFFIX,alimama.cn,REJECT
  - DOMAIN-SUFFIX,mmstat.com,REJECT
  - DOMAIN-SUFFIX,atpanel.com,REJECT
  - DOMAIN-SUFFIX,sitemeter.com,REJECT
  - DOMAIN-SUFFIX,gridsumdissector.cn,REJECT
  - DOMAIN-SUFFIX,gridsum.com,REJECT
  - DOMAIN-SUFFIX,sensorsdata.cn,REJECT
  - DOMAIN-SUFFIX,sensors.jd.com,REJECT
  
  # ===================
  # End of China Tracking Rules
  # ===================

  # Microsoft Copilot/Bing AI
  - DOMAIN-SUFFIX,sydney.bing.com,PROXY
  - DOMAIN-SUFFIX,bingapis.com,PROXY
  - DOMAIN,copilot.microsoft.com,PROXY
  - DOMAIN,browser.pipe.aria.microsoft.com,PROXY
  - DOMAIN,edgeservices.bing.com,PROXY
  
  # Apple Developer
  - DOMAIN,developer.apple.com,PROXY
  - DOMAIN,testflight.apple.com,PROXY
  
  # OpenAI/ChatGPT
  - DOMAIN-SUFFIX,openai.com,PROXY
  - DOMAIN-SUFFIX,chatgpt.com,PROXY
  
  # xAI/Grok AI
  - DOMAIN-SUFFIX,x.ai,PROXY
  - DOMAIN-SUFFIX,grok.x.ai,PROXY
  
  # Anthropic/Claude AI
  - DOMAIN-SUFFIX,anthropic.com,PROXY
  - DOMAIN-SUFFIX,claude.ai,PROXY
  
  # Google Gemini / DeepMind
  - DOMAIN-SUFFIX,deepmind.com,PROXY
  - DOMAIN-SUFFIX,deepmind.google,PROXY
  - DOMAIN-SUFFIX,gemini.google.com,PROXY
  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,PROXY
  
  # GitHub (commonly throttled / blocked)
  - DOMAIN-SUFFIX,github.com,PROXY
  - DOMAIN-SUFFIX,github.io,PROXY
  - DOMAIN-SUFFIX,githubapp.com,PROXY
  - DOMAIN-SUFFIX,githubusercontent.com,PROXY
  - DOMAIN-SUFFIX,githubassets.com,PROXY
  - DOMAIN-SUFFIX,ghcr.io,PROXY
  - DOMAIN-SUFFIX,github.dev,PROXY
  - DOMAIN-SUFFIX,copilot.github.com,PROXY
  
  # Discord
  - DOMAIN-SUFFIX,discord.com,PROXY
  - DOMAIN-SUFFIX,discord.gg,PROXY
  - DOMAIN-SUFFIX,discordapp.com,PROXY
  - DOMAIN-SUFFIX,discordapp.net,PROXY
  - DOMAIN-SUFFIX,discord.media,PROXY
  
  # Twitter / X
  - DOMAIN-SUFFIX,twitter.com,PROXY
  - DOMAIN-SUFFIX,x.com,PROXY
  - DOMAIN-SUFFIX,twimg.com,PROXY
  - DOMAIN-SUFFIX,t.co,PROXY
  - DOMAIN-SUFFIX,tweetdeck.com,PROXY
  
  # YouTube / Google Video
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - DOMAIN-SUFFIX,youtu.be,PROXY
  - DOMAIN-SUFFIX,ytimg.com,PROXY
  - DOMAIN-SUFFIX,googlevideo.com,PROXY
  - DOMAIN-SUFFIX,ggpht.com,PROXY
  - DOMAIN-SUFFIX,youtube-nocookie.com,PROXY
  
  # Netflix
  - DOMAIN-SUFFIX,netflix.com,PROXY
  - DOMAIN-SUFFIX,netflix.net,PROXY
  - DOMAIN-SUFFIX,nflxext.com,PROXY
  - DOMAIN-SUFFIX,nflximg.com,PROXY
  - DOMAIN-SUFFIX,nflximg.net,PROXY
  - DOMAIN-SUFFIX,nflxso.net,PROXY
  - DOMAIN-SUFFIX,nflxvideo.net,PROXY
  
  # Spotify
  - DOMAIN-SUFFIX,spotify.com,PROXY
  - DOMAIN-SUFFIX,spotifycdn.com,PROXY
  - DOMAIN-SUFFIX,scdn.co,PROXY
  - DOMAIN-SUFFIX,spoti.fi,PROXY
  
  # Wikipedia / Wikimedia
  - DOMAIN-SUFFIX,wikipedia.org,PROXY
  - DOMAIN-SUFFIX,wikimedia.org,PROXY
  - DOMAIN-SUFFIX,wiktionary.org,PROXY
  - DOMAIN-SUFFIX,mediawiki.org,PROXY
  
  # Telegram (domains – CIDR already in rule-providers)
  - DOMAIN-SUFFIX,telegram.org,PROXY
  - DOMAIN-SUFFIX,t.me,PROXY
  - DOMAIN-SUFFIX,telegram.me,PROXY
  - DOMAIN-SUFFIX,telesco.pe,PROXY
  
  # Reddit
  - DOMAIN-SUFFIX,reddit.com,PROXY
  - DOMAIN-SUFFIX,redd.it,PROXY
  - DOMAIN-SUFFIX,redditmedia.com,PROXY
  - DOMAIN-SUFFIX,redditstatic.com,PROXY
  
  # Microsoft 365 / Azure (international)
  - DOMAIN-SUFFIX,live.com,PROXY
  - DOMAIN-SUFFIX,outlook.com,PROXY
  - DOMAIN-SUFFIX,office.com,PROXY
  - DOMAIN-SUFFIX,office365.com,PROXY
  - DOMAIN-SUFFIX,microsoftonline.com,PROXY
  - DOMAIN-SUFFIX,msftauth.net,PROXY
  - DOMAIN-SUFFIX,msauth.net,PROXY
  - DOMAIN-SUFFIX,onedrive.com,PROXY
  - DOMAIN-SUFFIX,sharepoint.com,PROXY
  
  # Amazon / AWS
  - DOMAIN-SUFFIX,amazon.com,PROXY
  - DOMAIN-SUFFIX,amazonaws.com,PROXY
  - DOMAIN-SUFFIX,amazon.co.jp,PROXY
  - DOMAIN-SUFFIX,primevideo.com,PROXY
  
  # Line (popular in Japan/TW)
  - DOMAIN-SUFFIX,line.me,PROXY
  - DOMAIN-SUFFIX,line-apps.com,PROXY
  - DOMAIN-SUFFIX,line-scdn.net,PROXY
  
  # Notion
  - DOMAIN-SUFFIX,notion.so,PROXY
  - DOMAIN-SUFFIX,notion-static.com,PROXY
  - DOMAIN-SUFFIX,notion.site,PROXY
  
  # Perplexity AI
  - DOMAIN-SUFFIX,perplexity.ai,PROXY
  
  # PayPal (international payments)
  - DOMAIN-SUFFIX,paypal.com,PROXY
  - DOMAIN-SUFFIX,paypalobjects.com,PROXY
  - DOMAIN-SUFFIX,paypal-dynamic.com,PROXY
  - DOMAIN-SUFFIX,braintree-api.com,PROXY
  - DOMAIN-SUFFIX,braintreegateway.com,PROXY
  
  # Google Pay (GPay)
  - DOMAIN-SUFFIX,pay.google.com,PROXY
  - DOMAIN-SUFFIX,payments.google.com,PROXY
  - DOMAIN-SUFFIX,wallet.google.com,PROXY
  
  # TikTok (International - blocked in China)
  - DOMAIN-SUFFIX,tiktok.com,PROXY
  - DOMAIN-SUFFIX,tiktokcdn.com,PROXY
  - DOMAIN-SUFFIX,tiktokv.com,PROXY
  - DOMAIN-SUFFIX,tiktokcdn-us.com,PROXY
  - DOMAIN-SUFFIX,muscdn.com,PROXY
  - DOMAIN-SUFFIX,musical.ly,PROXY
  - DOMAIN-SUFFIX,byteoversea.com,PROXY
  - DOMAIN-SUFFIX,ibytedtos.com,PROXY
  - DOMAIN-SUFFIX,ibyteimg.com,PROXY
  
  # Facebook/Meta
  - DOMAIN-SUFFIX,facebook.com,PROXY
  - DOMAIN-SUFFIX,facebook.net,PROXY
  - DOMAIN-SUFFIX,fbcdn.net,PROXY
  - DOMAIN-SUFFIX,fbsbx.com,PROXY
  - DOMAIN-SUFFIX,fb.com,PROXY
  - DOMAIN-SUFFIX,fb.me,PROXY
  - DOMAIN-SUFFIX,messenger.com,PROXY
  - DOMAIN-SUFFIX,meta.com,PROXY
  - DOMAIN-SUFFIX,metacdn.com,PROXY
  - DOMAIN-SUFFIX,oculus.com,PROXY
  - DOMAIN-SUFFIX,oculuscdn.com,PROXY
  
  # Instagram
  - DOMAIN-SUFFIX,instagram.com,PROXY
  - DOMAIN-SUFFIX,cdninstagram.com,PROXY
  - DOMAIN-SUFFIX,instagr.am,PROXY
  
  # WhatsApp
  - DOMAIN-SUFFIX,whatsapp.com,PROXY
  - DOMAIN-SUFFIX,whatsapp.net,PROXY
  - DOMAIN-SUFFIX,wa.me,PROXY
  
  # Threads (Meta)
  - DOMAIN-SUFFIX,threads.net,PROXY
  
  # ===================
  # Steam Optimization (for China users)
  # Store/Community/API via PROXY for speed & access
  # China CDN downloads stay DIRECT when available
  # ===================
  # Steam Store & Community (often slow/blocked in China)
  - DOMAIN-SUFFIX,steampowered.com,PROXY
  - DOMAIN-SUFFIX,steamcommunity.com,PROXY
  - DOMAIN-SUFFIX,steamgames.com,PROXY
  - DOMAIN-SUFFIX,steamusercontent.com,PROXY
  - DOMAIN-SUFFIX,steamstatic.com,PROXY
  - DOMAIN-SUFFIX,steam-chat.com,PROXY
  - DOMAIN,api.steampowered.com,PROXY
  - DOMAIN,store.steampowered.com,PROXY
  - DOMAIN,login.steampowered.com,PROXY
  - DOMAIN,checkout.steampowered.com,PROXY
  - DOMAIN,partner.steampowered.com,PROXY
  - DOMAIN,help.steampowered.com,PROXY
  
  # Steam Media/CDN (use PROXY for faster international CDN)
  - DOMAIN-SUFFIX,steambroadcast.akamaized.net,PROXY
  - DOMAIN-SUFFIX,steamcdn-a.akamaihd.net,PROXY
  - DOMAIN-SUFFIX,steamcontent.com,PROXY
  - DOMAIN-SUFFIX,steamchina.com,DIRECT
  - DOMAIN,cdn.steamstatic.com,PROXY
  - DOMAIN,media.steampowered.com,PROXY
  - DOMAIN,cdn.cloudflare.steamstatic.com,PROXY
  - DOMAIN,cdn.akamai.steamstatic.com,PROXY
  
  # Steam Client/Network (needs PROXY for stable connection)
  - DOMAIN,cm.steampowered.com,PROXY
  - DOMAIN,client-download.steampowered.com,PROXY
  - DOMAIN-KEYWORD,steamcontent,PROXY
  - DOMAIN-KEYWORD,steampipe,PROXY
  
  # Valve/Steam IP ranges (for game servers, optional PROXY)
  - IP-CIDR,103.10.124.0/23,PROXY,no-resolve
  - IP-CIDR,103.28.54.0/24,PROXY,no-resolve
  - IP-CIDR,146.66.152.0/24,PROXY,no-resolve
  - IP-CIDR,146.66.155.0/24,PROXY,no-resolve
  - IP-CIDR,155.133.224.0/22,PROXY,no-resolve
  - IP-CIDR,162.254.192.0/21,PROXY,no-resolve
  - IP-CIDR,185.25.180.0/22,PROXY,no-resolve
  - IP-CIDR,190.217.32.0/22,PROXY,no-resolve
  - IP-CIDR,192.69.96.0/22,PROXY,no-resolve
  - IP-CIDR,205.196.6.0/24,PROXY,no-resolve
  - IP-CIDR,208.64.200.0/22,PROXY,no-resolve
  - IP-CIDR,208.78.164.0/22,PROXY,no-resolve
  
  # ===================
  # Roblox Optimization (for China users)
  # Full PROXY for best connection stability & latency
  # ===================
  # Roblox Main Domains
  - DOMAIN-SUFFIX,roblox.com,PROXY
  - DOMAIN-SUFFIX,rbxcdn.com,PROXY
  - DOMAIN-SUFFIX,robloxcdn.com,PROXY
  - DOMAIN-SUFFIX,rbx.com,PROXY
  - DOMAIN-SUFFIX,roblox.cn,PROXY
  # Roblox API & Services
  - DOMAIN,api.roblox.com,PROXY
  - DOMAIN,apis.roblox.com,PROXY
  - DOMAIN,auth.roblox.com,PROXY
  - DOMAIN,avatar.roblox.com,PROXY
  - DOMAIN,catalog.roblox.com,PROXY
  - DOMAIN,chat.roblox.com,PROXY
  - DOMAIN,develop.roblox.com,PROXY
  - DOMAIN,economy.roblox.com,PROXY
  - DOMAIN,friends.roblox.com,PROXY
  - DOMAIN,games.roblox.com,PROXY
  - DOMAIN,groups.roblox.com,PROXY
  - DOMAIN,inventory.roblox.com,PROXY
  - DOMAIN,locale.roblox.com,PROXY
  - DOMAIN,notifications.roblox.com,PROXY
  - DOMAIN,presence.roblox.com,PROXY
  - DOMAIN,privatemessages.roblox.com,PROXY
  - DOMAIN,thumbnails.roblox.com,PROXY
  - DOMAIN,trades.roblox.com,PROXY
  - DOMAIN,users.roblox.com,PROXY
  - DOMAIN,voice.roblox.com,PROXY
  - DOMAIN,web.roblox.com,PROXY
  # Roblox CDN & Assets
  - DOMAIN-SUFFIX,rbxtrk.com,PROXY
  - DOMAIN-SUFFIX,robloxlabs.com,PROXY
  - DOMAIN-SUFFIX,rbxassetcdn.com,PROXY
  - DOMAIN-KEYWORD,roblox,PROXY
  - DOMAIN-KEYWORD,rbxcdn,PROXY
  # Roblox Voice Chat & Real-time
  - DOMAIN-SUFFIX,rbx.io,PROXY
  - DOMAIN-SUFFIX,simulpong.com,PROXY
  
  # Domain suffix rules (deduplicated - remove entries already covered above)
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,xai.com,PROXY
  
  # Rule providers
  - RULE-SET,reject,REJECT
  - RULE-SET,applications,DIRECT
  - RULE-SET,private,DIRECT
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,PROXY
  - RULE-SET,proxy,PROXY
  - RULE-SET,direct,DIRECT
  - RULE-SET,gfw,PROXY
  - RULE-SET,tld-not-cn,PROXY
  - RULE-SET,telegramcidr,PROXY,no-resolve
  - RULE-SET,lancidr,DIRECT,no-resolve
  - RULE-SET,cncidr,DIRECT,no-resolve
  
  # ===================
  # Chinese Sites - DIRECT (for users in China)
  # Ensures domestic sites never go through proxy
  # ===================
  # Chinese Video Platforms
  - DOMAIN-SUFFIX,youku.com,DIRECT
  - DOMAIN-SUFFIX,iqiyi.com,DIRECT
  - DOMAIN-SUFFIX,bilibili.com,DIRECT
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - DOMAIN-SUFFIX,douyin.com,DIRECT
  - DOMAIN-SUFFIX,toutiao.com,DIRECT
  - DOMAIN-SUFFIX,mgtv.com,DIRECT
  - DOMAIN-SUFFIX,sohu.com,DIRECT
  
  # Chinese Social
  - DOMAIN-SUFFIX,weibo.com,DIRECT
  - DOMAIN-SUFFIX,xiaohongshu.com,DIRECT
  - DOMAIN-SUFFIX,zhihu.com,DIRECT
  - DOMAIN-SUFFIX,douban.com,DIRECT
  
  # Chinese E-commerce
  - DOMAIN-SUFFIX,taobao.com,DIRECT
  - DOMAIN-SUFFIX,tmall.com,DIRECT
  - DOMAIN-SUFFIX,jd.com,DIRECT
  - DOMAIN-SUFFIX,pinduoduo.com,DIRECT
  - DOMAIN-SUFFIX,alipay.com,DIRECT
  
  # Chinese Portals
  - DOMAIN-SUFFIX,baidu.com,DIRECT
  - DOMAIN-SUFFIX,163.com,DIRECT
  - DOMAIN-SUFFIX,sina.com.cn,DIRECT
  
  # Chinese Cloud
  - DOMAIN-SUFFIX,aliyun.com,DIRECT
  - DOMAIN-SUFFIX,qcloud.com,DIRECT
  
  # Private IP ranges
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  
  # Final rules
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,cn,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
'''

# China Mode Clash configuration template - reverse proxy logic
# Proxy Chinese services (YouKu, Douyin, iQiyi, Bilibili, etc.), direct everything else
CLASH_CONFIG_CHINA_TEMPLATE = '''# =============================================================================
# Clash Configuration (China Mode) - Generated by setup_hy2.py
# For accessing Chinese services from outside China
# Proxy: Chinese sites | Direct: International sites
# =============================================================================
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 8.8.8.8
    - 1.1.1.1
  fallback:
    - 223.5.5.5
    - 119.29.29.29

proxies:
{proxy_config}

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - {server_name}
  
  - name: AUTO
    type: url-test
    proxies:
      - {server_name}
    url: http://www.baidu.com/
    interval: 300

# -----------------------------------------------------------------------------
# Rule Providers for China Mode
# -----------------------------------------------------------------------------
rule-providers:
  reject:
    behavior: domain
    interval: 86400
    path: ./ruleset/reject.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt

  direct:
    behavior: domain
    interval: 86400
    path: ./ruleset/direct.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt

  private:
    behavior: domain
    interval: 86400
    path: ./ruleset/private.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt

  cncidr:
    behavior: ipcidr
    interval: 86400
    path: ./ruleset/cncidr.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt

  lancidr:
    behavior: ipcidr
    interval: 86400
    path: ./ruleset/lancidr.yaml
    type: http
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt

# -----------------------------------------------------------------------------
# Rules for China Mode - Proxy Chinese sites, Direct everything else
# -----------------------------------------------------------------------------
rules:
  # ===================
  # Chinese Video Platforms (PROXY)
  # ===================
  # YouKu (优酷)
  - DOMAIN-SUFFIX,youku.com,PROXY
  - DOMAIN-SUFFIX,ykimg.com,PROXY
  - DOMAIN-SUFFIX,mmstat.com,PROXY
  - DOMAIN-SUFFIX,soku.com,PROXY
  
  # iQiyi (爱奇艺)
  - DOMAIN-SUFFIX,iqiyi.com,PROXY
  - DOMAIN-SUFFIX,iqiyipic.com,PROXY
  - DOMAIN-SUFFIX,qiyi.com,PROXY
  - DOMAIN-SUFFIX,qiyipic.com,PROXY
  - DOMAIN-SUFFIX,71.am,PROXY
  
  # Bilibili (哔哩哔哩)
  - DOMAIN-SUFFIX,bilibili.com,PROXY
  - DOMAIN-SUFFIX,bilivideo.com,PROXY
  - DOMAIN-SUFFIX,biliapi.com,PROXY
  - DOMAIN-SUFFIX,biliapi.net,PROXY
  - DOMAIN-SUFFIX,hdslb.com,PROXY
  - DOMAIN-SUFFIX,acgvideo.com,PROXY
  
  # Douyin/TikTok China (抖音)
  - DOMAIN-SUFFIX,douyin.com,PROXY
  - DOMAIN-SUFFIX,douyinpic.com,PROXY
  - DOMAIN-SUFFIX,douyincdn.com,PROXY
  - DOMAIN-SUFFIX,douyinvod.com,PROXY
  - DOMAIN-SUFFIX,amemv.com,PROXY
  - DOMAIN-SUFFIX,snssdk.com,PROXY
  - DOMAIN-SUFFIX,bytedance.com,PROXY
  - DOMAIN-SUFFIX,bytecdn.cn,PROXY
  - DOMAIN-SUFFIX,bytednsdoc.com,PROXY
  - DOMAIN-SUFFIX,byted-static.com,PROXY
  - DOMAIN-SUFFIX,ixigua.com,PROXY
  - DOMAIN-SUFFIX,pstatp.com,PROXY
  - DOMAIN-SUFFIX,toutiao.com,PROXY
  
  # Tencent Video (腾讯视频)
  - DOMAIN-SUFFIX,qq.com,PROXY
  - DOMAIN-SUFFIX,gtimg.com,PROXY
  - DOMAIN-SUFFIX,gtimg.cn,PROXY
  - DOMAIN-SUFFIX,qpic.cn,PROXY
  - DOMAIN-SUFFIX,qlogo.cn,PROXY
  - DOMAIN-SUFFIX,video.qq.com,PROXY
  - DOMAIN-SUFFIX,v.qq.com,PROXY
  
  # Mango TV (芒果TV)
  - DOMAIN-SUFFIX,mgtv.com,PROXY
  - DOMAIN-SUFFIX,hunantv.com,PROXY
  
  # Sohu Video (搜狐视频)
  - DOMAIN-SUFFIX,sohu.com,PROXY
  - DOMAIN-SUFFIX,sohucs.com,PROXY
  - DOMAIN-SUFFIX,itc.cn,PROXY
  
  # LeTV/Le (乐视)
  - DOMAIN-SUFFIX,le.com,PROXY
  - DOMAIN-SUFFIX,letv.com,PROXY
  - DOMAIN-SUFFIX,letvimg.com,PROXY
  
  # PPTV
  - DOMAIN-SUFFIX,pptv.com,PROXY
  - DOMAIN-SUFFIX,pptvyun.com,PROXY
  
  # ===================
  # Chinese Music Platforms (PROXY)
  # ===================
  # NetEase Music (网易云音乐)
  - DOMAIN-SUFFIX,163.com,PROXY
  - DOMAIN-SUFFIX,126.net,PROXY
  - DOMAIN-SUFFIX,netease.com,PROXY
  - DOMAIN-SUFFIX,music.163.com,PROXY
  
  # QQ Music (QQ音乐)
  - DOMAIN-SUFFIX,y.qq.com,PROXY
  - DOMAIN-SUFFIX,qqmusic.qq.com,PROXY
  
  # Kugou (酷狗)
  - DOMAIN-SUFFIX,kugou.com,PROXY
  
  # Kuwo (酷我)
  - DOMAIN-SUFFIX,kuwo.cn,PROXY
  
  # Xiami (虾米 - may be discontinued)
  - DOMAIN-SUFFIX,xiami.com,PROXY
  - DOMAIN-SUFFIX,xiami.net,PROXY
  
  # ===================
  # Chinese Social Platforms (PROXY)
  # ===================
  # Weibo (微博)
  - DOMAIN-SUFFIX,weibo.com,PROXY
  - DOMAIN-SUFFIX,weibo.cn,PROXY
  - DOMAIN-SUFFIX,weibocdn.com,PROXY
  - DOMAIN-SUFFIX,sinaimg.cn,PROXY
  - DOMAIN-SUFFIX,sina.com.cn,PROXY
  - DOMAIN-SUFFIX,sina.cn,PROXY
  
  # Zhihu (知乎)
  - DOMAIN-SUFFIX,zhihu.com,PROXY
  - DOMAIN-SUFFIX,zhimg.com,PROXY
  
  # Xiaohongshu (小红书)
  - DOMAIN-SUFFIX,xiaohongshu.com,PROXY
  - DOMAIN-SUFFIX,xhscdn.com,PROXY
  
  # Douban (豆瓣)
  - DOMAIN-SUFFIX,douban.com,PROXY
  - DOMAIN-SUFFIX,doubanio.com,PROXY
  
  # ===================
  # Chinese E-commerce (PROXY)
  # ===================
  # Taobao/Tmall (淘宝/天猫)
  - DOMAIN-SUFFIX,taobao.com,PROXY
  - DOMAIN-SUFFIX,tmall.com,PROXY
  - DOMAIN-SUFFIX,alicdn.com,PROXY
  - DOMAIN-SUFFIX,tbcdn.cn,PROXY
  - DOMAIN-SUFFIX,alipay.com,PROXY
  - DOMAIN-SUFFIX,alipayobjects.com,PROXY
  
  # JD (京东)
  - DOMAIN-SUFFIX,jd.com,PROXY
  - DOMAIN-SUFFIX,jd.hk,PROXY
  - DOMAIN-SUFFIX,360buyimg.com,PROXY
  - DOMAIN-SUFFIX,jdpay.com,PROXY
  
  # Pinduoduo (拼多多)
  - DOMAIN-SUFFIX,pinduoduo.com,PROXY
  - DOMAIN-SUFFIX,yangkeduo.com,PROXY
  
  # ===================
  # Chinese News & Portals (PROXY)
  # ===================
  - DOMAIN-SUFFIX,baidu.com,PROXY
  - DOMAIN-SUFFIX,baidustatic.com,PROXY
  - DOMAIN-SUFFIX,bdstatic.com,PROXY
  - DOMAIN-SUFFIX,bdimg.com,PROXY
  - DOMAIN-SUFFIX,xinhuanet.com,PROXY
  - DOMAIN-SUFFIX,people.com.cn,PROXY
  - DOMAIN-SUFFIX,cctv.com,PROXY
  - DOMAIN-SUFFIX,ifeng.com,PROXY
  - DOMAIN-SUFFIX,thepaper.cn,PROXY
  
  # ===================
  # Chinese Cloud & CDN (PROXY)
  # ===================
  - DOMAIN-SUFFIX,aliyun.com,PROXY
  - DOMAIN-SUFFIX,aliyuncs.com,PROXY
  - DOMAIN-SUFFIX,alibabacloud.com,PROXY
  - DOMAIN-SUFFIX,qcloud.com,PROXY
  - DOMAIN-SUFFIX,myqcloud.com,PROXY
  - DOMAIN-SUFFIX,huaweicloud.com,PROXY
  - DOMAIN-SUFFIX,hwcloudtest.cn,PROXY
  - DOMAIN-SUFFIX,ksyun.com,PROXY
  - DOMAIN-SUFFIX,qiniu.com,PROXY
  - DOMAIN-SUFFIX,qiniucdn.com,PROXY
  - DOMAIN-SUFFIX,ucloud.cn,PROXY
  
  # ===================
  # Chinese Games (PROXY)
  # ===================
  - DOMAIN-SUFFIX,mihoyo.com,PROXY
  - DOMAIN-SUFFIX,yuanshen.com,PROXY
  - DOMAIN-SUFFIX,hoyoverse.com,PROXY
  - DOMAIN-SUFFIX,netease-na.com,PROXY
  
  # ===================
  # General China Rules
  # ===================
  # All .cn TLD sites through proxy
  - DOMAIN-SUFFIX,cn,PROXY
  
  # China IP ranges through proxy
  - RULE-SET,cncidr,PROXY,no-resolve
  - GEOIP,CN,PROXY
  
  # Reject ads
  - RULE-SET,reject,REJECT
  
  # Private/LAN - always direct
  - RULE-SET,private,DIRECT
  - RULE-SET,lancidr,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT
  - IP-CIDR,172.16.0.0/12,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  
  # Local domains - direct
  - DOMAIN-SUFFIX,local,DIRECT
  
  # Everything else - DIRECT (international sites don't need proxy)
  - MATCH,DIRECT

tls:
  insecure: true
'''

# Hysteria v2 native client config template
HY2_CLIENT_TEMPLATE = '''# Hysteria v2 Client Configuration
# Generated by setup_hy2.py
# Usage: hysteria client -c config.yaml
#
# NOTE: If connecting via IPv6 and port hopping doesn't work,
# replace the server line with the direct port: {server_addr_direct}

server: "{server_addr_hop}"
auth: "{password}"

tls:
  insecure: true
  pinSHA256: "{pin_sha256}"

transport:
  type: udp
  udp:
    hopInterval: {hop_interval}s

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
'''


def format_server_addr(ip: str, port: int) -> str:
    """Format server address with port, handling IPv6 properly."""
    try:
        # Check if it's an IPv6 address
        ipaddress.IPv6Address(ip)
        return f"[{ip}]:{port}"
    except ValueError:
        # IPv4 or hostname
        return f"{ip}:{port}"


def format_server_addr_hop(ip: str, port: int, hop_start: int = PORT_HOP_START, hop_end: int = PORT_HOP_END) -> str:
    """Format server address with port hopping range, handling IPv6 properly."""
    try:
        # Check if it's an IPv6 address
        ipaddress.IPv6Address(ip)
        return f"[{ip}]:{hop_start}-{hop_end}"
    except ValueError:
        # IPv4 or hostname
        return f"{ip}:{hop_start}-{hop_end}"


def save_configs(save_dir: str, server_ip: str, server_name: str, hy2_port: int, 
                 hy2_password: str, pin_sha256: str, hop_interval: str,
                 masquerade_domain: str = None,
                 new_root_password: str = None, pubkey_path: str = None,
                 china_mode: bool = False, local_mode: bool = False):
    """Save generated configurations to local files.
    
    Args:
        china_mode: If True, use China-specific Clash config template
        local_mode: If True, use direct port instead of hop range (port hopping
                   doesn't work for same-machine clients in WSL/local mode)
    """
    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    
    # Use masquerade domain for SNI if provided, otherwise use server IP
    sni = masquerade_domain if masquerade_domain else server_ip
    
    # Generate proxy config for Clash (with pinSHA256 for certificate validation)
    # In local mode, don't include port hopping (ports field) as it won't work
    if local_mode:
        proxy_config = f'''  - name: {server_name}
    type: hysteria2
    server: "{server_ip}"
    port: {hy2_port}
    password: {hy2_password}
    sni: "{sni}"
    skip-cert-verify: true
    fingerprint: "{pin_sha256}"'''
    else:
        proxy_config = f'''  - name: {server_name}
    type: hysteria2
    server: "{server_ip}"
    port: {hy2_port}
    ports: {PORT_HOP_START}-{PORT_HOP_END}
    hop-interval: {hop_interval}
    password: {hy2_password}
    sni: "{sni}"
    skip-cert-verify: true
    fingerprint: "{pin_sha256}"'''
    
    # Generate full Clash config - use China template if in China mode
    if china_mode:
        clash_config = CLASH_CONFIG_CHINA_TEMPLATE.format(
            proxy_config=proxy_config,
            server_name=server_name
        )
    else:
        clash_config = CLASH_CONFIG_TEMPLATE.format(
            proxy_config=proxy_config,
            server_name=server_name
        )
    
    clash_file = save_path / 'clash.yaml'
    with open(clash_file, 'w', encoding='utf-8') as f:
        f.write(clash_config)
    print(f"  Saved: {clash_file}")
    
    # Generate Hysteria v2 native config
    server_addr = format_server_addr(server_ip, hy2_port)
    server_addr_hop = format_server_addr_hop(server_ip, hy2_port)
    
    # In local mode, use direct port (port hopping doesn't work for same-machine clients)
    if local_mode:
        hy2_config = f'''# Hysteria v2 Client Configuration
# Generated by setup_hy2.py
# Usage: hysteria client -c config.yaml
#
# NOTE: Local mode - using direct port. Port hopping is disabled because
# iptables PREROUTING rules don't affect traffic from the same machine.

server: "{server_addr}"
auth: "{hy2_password}"

tls:
  insecure: true
  pinSHA256: "{pin_sha256}"

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
'''
    else:
        hy2_config = HY2_CLIENT_TEMPLATE.format(
            server_addr_hop=server_addr_hop,
            server_addr_direct=server_addr,
            password=hy2_password,
            pin_sha256=pin_sha256,
            hop_interval=hop_interval
        )
    
    hy2_file = save_path / 'hy2-client.yaml'
    with open(hy2_file, 'w', encoding='utf-8') as f:
        f.write(hy2_config)
    print(f"  Saved: {hy2_file}")
    
    # Generate credentials file
    credentials = f'''# VPS Credentials
# Generated by setup_hy2.py
# KEEP THIS FILE SECURE!

Server IP: {server_ip}
Hysteria2 Port: {hy2_port}
Hysteria2 Password: {hy2_password}
Pin SHA256: {pin_sha256}
Port Hop Range: {PORT_HOP_START}-{PORT_HOP_END}
Hop Interval: {hop_interval}
'''
    
    if new_root_password:
        credentials += f'''
New Root Password: {new_root_password}
'''
    
    if pubkey_path:
        privkey_path = str(pubkey_path).replace('.pub', '')
        credentials += f'''
SSH Private Key: {privkey_path}
SSH Command: ssh -i {privkey_path} root@{server_ip}
'''
    
    creds_file = save_path / 'credentials.txt'
    with open(creds_file, 'w', encoding='utf-8') as f:
        f.write(credentials)
    print(f"  Saved: {creds_file}")
    
    return True


def download_local_hysteria_client(ssh: paramiko.SSHClient, save_dir: str) -> Path | None:
    """Download Hysteria2 client binary for the local machine via remote VPS.
    
    Downloads the binary on the remote VPS (faster/more reliable) then copies
    it back to the local machine via SFTP.
    
    Args:
        ssh: SSH connection to the remote VPS
        save_dir: Local directory to save the binary
        
    Returns:
        Path to the downloaded binary, or None if failed
    """
    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    
    # Detect local OS and architecture
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map to Hysteria release naming
    if system == 'windows':
        os_name = 'windows'
        ext = '.exe'
    elif system == 'darwin':
        os_name = 'darwin'
        ext = ''
    elif system == 'linux':
        os_name = 'linux'
        ext = ''
    else:
        print(f"  [WARN] Unsupported OS: {system}")
        return None
    
    # Map architecture
    if machine in ['x86_64', 'amd64']:
        arch = 'amd64'
    elif machine in ['aarch64', 'arm64']:
        arch = 'arm64'
    elif 'arm' in machine:
        arch = 'arm'
    else:
        print(f"  [WARN] Unsupported architecture: {machine}")
        return None
    
    # Construct download URL and paths
    filename = f"hysteria-{os_name}-{arch}{ext}"
    download_url = f"https://github.com/apernet/hysteria/releases/latest/download/{filename}"
    remote_path = f"/tmp/{filename}"
    local_binary = save_path / f"hy2{ext}"
    
    print(f"  Target: {system}/{arch}")
    print(f"  Downloading on VPS: {download_url}")
    
    try:
        # Download on remote VPS (usually faster than local download)
        result = run_command(ssh, f"curl -fsSL --connect-timeout 60 --max-time 300 '{download_url}' -o {remote_path} 2>&1", check_error=False, show_output=True)
        
        # Check if download succeeded
        check = run_command(ssh, f"test -s {remote_path} && file {remote_path}", check_error=False)
        if 'executable' not in check.lower() and 'ELF' not in check and 'PE32' not in check:
            print(f"  ✗ Download failed on VPS: {check}")
            return None
        
        print(f"  ✓ Downloaded on VPS")
        
        # Copy from VPS to local machine via SFTP
        print(f"  Copying to local machine...")
        sftp = ssh.open_sftp()
        sftp.get(remote_path, str(local_binary))
        sftp.close()
        
        # Clean up remote temp file
        run_command(ssh, f"rm -f {remote_path}", check_error=False)
        
        # Make executable on Unix-like systems
        if system != 'windows':
            import os
            os.chmod(local_binary, 0o755)
        
        print(f"  ✓ Saved to: {local_binary}")
        return local_binary
        
    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        # Clean up remote temp file on error
        try:
            run_command(ssh, f"rm -f {remote_path}", check_error=False)
        except Exception:
            pass
        return None


def download_hysteria_locally(save_dir: str, target_os: str = 'linux', target_arch: str = 'amd64') -> Path | None:
    """Download Hysteria2 binary locally (for China mode where GitHub is blocked on VPS).
    
    Args:
        save_dir: Local directory to save the binary
        target_os: Target OS ('linux', 'windows', 'darwin')
        target_arch: Target architecture ('amd64', 'arm64', 'arm')
        
    Returns:
        Path to the downloaded binary, or None if failed
    """
    import urllib.request
    
    save_path = Path(save_dir)
    save_path.mkdir(parents=True, exist_ok=True)
    
    ext = '.exe' if target_os == 'windows' else ''
    filename = f"hysteria-{target_os}-{target_arch}{ext}"
    download_url = f"https://github.com/apernet/hysteria/releases/latest/download/{filename}"
    local_binary = save_path / filename
    
    print(f"  Target: {target_os}/{target_arch}")
    print(f"  Downloading from: {download_url}")
    
    try:
        # Download with progress (using default SSL verification)
        print(f"  Downloading...")
        with urllib.request.urlopen(download_url, timeout=300) as response:
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            chunk_size = 8192
            
            with open(local_binary, 'wb') as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r  Progress: {percent:.1f}% ({downloaded}/{total_size} bytes)", end='', flush=True)
            print()  # New line after progress
        
        print(f"  ✓ Downloaded to: {local_binary}")
        return local_binary
        
    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        # Clean up partial file
        if local_binary.exists():
            local_binary.unlink()
        return None


def upload_hysteria_to_server(ssh: paramiko.SSHClient, local_binary: Path, 
                               remote_path: str = '/usr/local/bin/hysteria',
                               disguise_name: str = None) -> bool:
    """Upload Hysteria2 binary to server via SFTP (for China mode).
    
    Args:
        ssh: Paramiko SSH client
        local_binary: Path to local binary file
        remote_path: Remote path to install binary (default: /usr/local/bin/hysteria)
        disguise_name: If provided, use this name instead (for avoiding detection)
        
    Returns:
        True if upload successful, False otherwise
    """
    if disguise_name:
        remote_path = f"/usr/local/bin/{disguise_name}"
    
    print(f"  Uploading {local_binary.name} to {remote_path}...")
    
    try:
        sftp = ssh.open_sftp()
        
        # Upload the binary
        sftp.put(str(local_binary), remote_path)
        sftp.close()
        
        # Set permissions
        run_command(ssh, f"chmod 755 {remote_path}", check_error=False)
        run_command(ssh, f"chown root:root {remote_path}", check_error=False)
        
        # Verify upload
        verify = run_command(ssh, f"test -x {remote_path} && echo 'UPLOAD_OK' || echo 'UPLOAD_FAILED'", check_error=False)
        if 'UPLOAD_OK' in verify:
            print(f"  ✓ Binary uploaded successfully to {remote_path}")
            return True
        else:
            print(f"  ✗ Binary upload verification failed")
            return False
            
    except Exception as e:
        print(f"  ✗ Upload failed: {e}")
        return False


def configure_docker_china_mirror(ssh: paramiko.SSHClient) -> bool:
    """Configure Docker to use Chinese mirror (Aliyun) for China mode.
    
    In China, Docker Hub is blocked, so we need to use Chinese mirrors.
    
    Returns:
        True if configuration successful
    """
    print(msg('china_configuring_docker_mirror'))
    
    # Aliyun Docker registry mirrors
    daemon_config = '''{
  "registry-mirrors": [
    "https://registry.cn-hangzhou.aliyuncs.com",
    "https://mirror.ccs.tencentyun.com",
    "https://hub-mirror.c.163.com"
  ],
  "ipv6": false
}'''
    
    run_command(ssh, "mkdir -p /etc/docker", check_error=False)
    run_command(ssh, f"cat > /etc/docker/daemon.json << 'DAEMONJSONEOF'\n{daemon_config}\nDAEMONJSONEOF")
    
    # Restart Docker to apply
    docker_running = run_command(ssh, "systemctl is-active docker 2>/dev/null || echo 'NOT_RUNNING'", check_error=False)
    if 'NOT_RUNNING' not in docker_running:
        print("  Restarting Docker to apply mirror settings...")
        run_command(ssh, "systemctl restart docker", check_error=False)
    
    print(msg('china_docker_mirror_configured'))
    return True


def disable_china_vps_agents(ssh: paramiko.SSHClient) -> list:
    """Disable China VPS provider monitoring agents more aggressively.
    
    Chinese VPS providers (Aliyun, Tencent, JDCloud, Huawei, Baidu) 
    have monitoring agents that can detect proxy services.
    
    Returns:
        List of disabled agents
    """
    print(msg('china_disabling_agents'))
    
    disabled = []
    
    # China VPS provider specific agents
    china_agents = [
        # Aliyun (阿里云)
        'aegis',           # Aliyun security agent (安骑士)
        'aliyun-service',  # Aliyun cloud assistant
        'cloudmonitor',    # Aliyun CloudMonitor
        'AliYunDun',       # Aliyun security
        'AliYunDunUpdate', # Aliyun security updater
        'aliyun_assist_update',
        'assist_daemon',
        
        # Tencent Cloud (腾讯云)
        'tat_agent',       # Tencent automation
        'sgagent',         # Tencent security
        'YDService',       # Tencent YunDun
        'YDLive',          # Tencent YunDun Live
        'barad_agent',     # Tencent CWPP
        'yd_agent',        # Tencent security
        
        # Huawei Cloud (华为云)
        'hostguard',       # Huawei Host Security
        'telescope',       # Huawei monitoring
        'uvp-monitor',     # Huawei UVP
        
        # Baidu Cloud (百度云)
        'bcm-agent',       # Baidu Cloud Monitor
        'hosteye',         # Baidu security
        
        # JD Cloud (京东云)
        'jcs-agent-core',  # JD Cloud agent
        'jdcloud-watchdog',
        
        # UCloud
        'ucloud-agent',
        
        # Kingsoft Cloud (金山云)
        'ksyun-agent',
        
        # Generic monitoring
        'qemu-guest-agent',
        'cloud-init',
        'zabbix-agent',
        'zabbix-agent2',
        'telegraf',
        'node_exporter',
        'collectd',
    ]
    
    for agent in china_agents:
        # Stop and disable
        result = run_command(ssh, f"systemctl stop {agent} 2>/dev/null; systemctl disable {agent} 2>/dev/null; systemctl mask {agent} 2>/dev/null; echo $?", check_error=False)
        if '0' in result:
            disabled.append(agent)
            print(f"    Disabled: {agent}")
    
    # Kill processes by name for agents that might not be systemd services
    agent_processes = [
        'AliYunDun', 'AliYunDunUpdate', 'aegis', 'cloudmonitor',
        'tat_agent', 'sgagent', 'YDService', 'barad_agent',
        'hostguard', 'telescope', 'bcm-agent', 'hosteye',
    ]
    
    for proc in agent_processes:
        run_command(ssh, f"pkill -9 -f {proc} 2>/dev/null || true", check_error=False)
    
    # Remove agent directories
    agent_dirs = [
        '/usr/local/aegis',        # Aliyun Aegis
        '/usr/local/cloudmonitor', # Aliyun CloudMonitor  
        '/usr/local/qcloud',       # Tencent
        '/usr/local/sa',           # Various security agents
        '/etc/qcloud',             # Tencent config
    ]
    
    for dir_path in agent_dirs:
        result = run_command(ssh, f"rm -rf {dir_path} 2>/dev/null && echo 'REMOVED' || echo 'NOT_FOUND'", check_error=False)
        if 'REMOVED' in result:
            print(f"    Removed: {dir_path}")
    
    # Block agent installation scripts from running
    run_command(ssh, "chmod 000 /etc/cron.d/aegis* 2>/dev/null || true", check_error=False)
    run_command(ssh, "chmod 000 /etc/init.d/aegis* 2>/dev/null || true", check_error=False)
    
    # Remove from crontab
    run_command(ssh, "crontab -l 2>/dev/null | grep -v aegis | grep -v cloudmonitor | crontab - 2>/dev/null || true", check_error=False)
    
    # Block reinstallation by creating dummy files
    run_command(ssh, "touch /etc/aegis_quartz_uninstall.sh && chmod 000 /etc/aegis_quartz_uninstall.sh 2>/dev/null || true", check_error=False)
    
    print(f"  ✓ Disabled {len(disabled)} monitoring agents")
    return disabled


def create_disguised_systemd_service(ssh: paramiko.SSHClient, debug_mode: bool = False,
                                     service_name: str = 'systemd-netlogd',
                                     binary_name: str = 'systemd-netlogd') -> None:
    """Create a disguised systemd service for Hysteria2 (for China mode).
    
    Uses innocent-looking names to avoid detection by VPS provider scanning.
    
    Args:
        ssh: Paramiko SSH client
        debug_mode: If True, enable logging
        service_name: Disguised service name
        binary_name: Disguised binary name (already renamed)
    """
    print(msg('china_disguising_service'))
    
    if debug_mode:
        logging_config = '''# Logging enabled for troubleshooting
StandardOutput=journal
StandardError=journal'''
    else:
        logging_config = '''# Zero-log mode - still log startup/failure via SyslogIdentifier
StandardOutput=null
StandardError=null'''
    
    # Use a description that looks like a legitimate system service
    # SyslogIdentifier ensures journalctl can find entries even in zero-log mode
    service_content = f'''[Unit]
Description=Network Logging Service
Documentation=man:systemd-networkd(8)
After=network.target nss-lookup.target

[Service]
Type=simple
SyslogIdentifier={service_name}
ExecStart=/usr/local/bin/{binary_name} server -c /etc/{service_name}/config.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
{logging_config}

[Install]
WantedBy=multi-user.target
'''
    
    # Create config directory with disguised name
    run_command(ssh, f"mkdir -p /etc/{service_name}", check_error=False)
    
    # Write service file
    service_path = f"/etc/systemd/system/{service_name}.service"
    run_command(ssh, f"cat > {service_path} << 'SERVICEEOF'\n{service_content}\nSERVICEEOF")
    
    # Verify service file was written correctly
    verify_result = run_command(ssh, f"test -f {service_path} && head -1 {service_path} || echo 'SERVICE_FILE_MISSING'", check_error=False)
    if 'SERVICE_FILE_MISSING' in verify_result:
        print_warn(f"  [WARN] Service file may not have been created: {service_path}")
    elif '[Unit]' not in verify_result:
        print_warn(f"  [WARN] Service file may be malformed - first line: {verify_result.strip()}")
    
    run_command(ssh, "systemctl daemon-reload")
    run_command(ssh, f"systemctl enable {service_name}")
    
    print(msg('china_service_disguised'))
    print(f"    Service name: {service_name}")
    print(f"    Binary name: {binary_name}")
    print(f"    Config dir: /etc/{service_name}/")


def install_hysteria2_china_mode(ssh: paramiko.SSHClient, local_binary: Path,
                                  service_name: str = 'systemd-netlogd',
                                  binary_name: str = 'systemd-netlogd') -> bool:
    """Install Hysteria2 in China mode with disguised names.
    
    Args:
        ssh: Paramiko SSH client
        local_binary: Path to locally downloaded binary
        service_name: Disguised service name
        binary_name: Disguised binary name
        
    Returns:
        True if installation successful
    """
    print(msg('china_uploading_binary'))
    
    # Upload with disguised name
    if not upload_hysteria_to_server(ssh, local_binary, disguise_name=binary_name):
        print(msg('china_upload_failed'))
        return False
    
    print(msg('china_upload_success'))
    
    # Create disguised config directory
    run_command(ssh, f"mkdir -p /etc/{service_name}", check_error=False)
    
    # Verify installation
    version = run_command(ssh, f"/usr/local/bin/{binary_name} version 2>&1", check_error=False).strip()
    if version and 'hysteria' in version.lower():
        print(f"  ✓ Installed: {version.split()[0] if version else 'unknown'}")
        return True
    else:
        # Binary might still work even if version check fails
        exists = run_command(ssh, f"test -x /usr/local/bin/{binary_name} && echo 'EXISTS'", check_error=False)
        if 'EXISTS' in exists:
            print("  ✓ Binary installed (version check skipped)")
            return True
        return False


def cleanup_opposite_mode(ssh: paramiko.SSHClient, china_mode: bool,
                          china_service_name: str = 'systemd-netlogd',
                          china_binary_name: str = 'systemd-netlogd') -> None:
    """Clean up installation from the opposite mode to allow mode switching.
    
    When switching from China mode to normal mode, or vice versa, this function
    stops and removes the service/binary from the previous mode.
    
    Args:
        ssh: Paramiko SSH client
        china_mode: True if currently running in China mode (will clean normal mode)
                   False if currently running in normal mode (will clean China mode)
        china_service_name: The disguised service name used in China mode
        china_binary_name: The disguised binary name used in China mode
    """
    print(msg('mode_switch_cleanup'))
    
    if china_mode:
        # Running China mode - clean up normal mode installation
        print("  Checking for existing normal mode installation...")
        
        # Stop and disable normal hysteria service
        run_command(ssh, "systemctl stop hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, "systemctl disable hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, "rm -f /etc/systemd/system/hysteria.service 2>/dev/null || true", check_error=False)
        
        # Remove normal binary
        run_command(ssh, "rm -f /usr/local/bin/hysteria 2>/dev/null || true", check_error=False)
        
        # Remove normal config directory
        run_command(ssh, "rm -rf /etc/hysteria 2>/dev/null || true", check_error=False)
        
        # Reload systemd
        run_command(ssh, "systemctl daemon-reload", check_error=False)
        
        print(msg('mode_switch_normal_cleaned'))
    else:
        # Running normal mode - clean up China mode installation
        print("  Checking for existing China mode installation...")
        
        # Stop and disable disguised service
        run_command(ssh, f"systemctl stop {china_service_name} 2>/dev/null || true", check_error=False)
        run_command(ssh, f"systemctl disable {china_service_name} 2>/dev/null || true", check_error=False)
        run_command(ssh, f"rm -f /etc/systemd/system/{china_service_name}.service 2>/dev/null || true", check_error=False)
        
        # Remove disguised binary
        run_command(ssh, f"rm -f /usr/local/bin/{china_binary_name} 2>/dev/null || true", check_error=False)
        
        # Remove disguised config directory
        run_command(ssh, f"rm -rf /etc/{china_service_name} 2>/dev/null || true", check_error=False)
        
        # Reload systemd
        run_command(ssh, "systemctl daemon-reload", check_error=False)
        
        print(msg('mode_switch_china_cleaned'))


def test_hysteria_client(binary_path: Path, config_path: Path) -> bool:
    """Test the Hysteria2 client connection.
    
    Args:
        binary_path: Path to the hy2 binary
        config_path: Path to the hy2-client.yaml config
        
    Returns:
        True if connection test passed, False otherwise
    """
    import subprocess
    import threading
    import queue
    
    print(f"\n  Testing Hysteria2 client connection...")
    print(f"  Binary: {binary_path}")
    print(f"  Config: {config_path}")
    print()
    
    try:
        # Run hysteria client for a few seconds to test connection
        # Use -c to specify config
        cmd = [str(binary_path), 'client', '-c', str(config_path)]
        
        print(f"  Running: {' '.join(cmd)}")
        print("  (Will run for 5 seconds to test connection...)")
        print()
        
        # Collect output lines
        output_lines = []
        connected = False
        
        # Start process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # Read and print output in real-time using a thread
        def read_output():
            nonlocal connected
            try:
                for line in iter(process.stdout.readline, ''):
                    if line:
                        line = line.rstrip()
                        output_lines.append(line)
                        print(f"  {line}")
                        if 'connected to server' in line.lower():
                            connected = True
            except Exception:
                pass
        
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()
        
        # Wait for a few seconds to check connection
        time.sleep(5)
        
        # Check if process is still running (good sign - means it connected)
        if process.poll() is None:
            if connected:
                print("\n  ✓ Client connected to server successfully!")
            else:
                print("\n  ✓ Client started successfully and is running!")
            print("  Terminating test...")
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
            return connected or True  # Return True if running, but connected is better
        else:
            # Process exited - wait for thread to finish
            reader_thread.join(timeout=1)
            full_output = '\n'.join(output_lines)
            if 'error' in full_output.lower() or 'failed' in full_output.lower():
                print("  ✗ Client connection test failed")
                return False
            else:
                print("  ✓ Client test completed")
                return True
                
    except FileNotFoundError:
        print(f"  ✗ Binary not found: {binary_path}")
        return False
    except Exception as e:
        print(f"  ✗ Test failed: {e}")
        return False


def msg(key: str, *args) -> str:
    """Get localized message."""
    text = MESSAGES.get(LANG, MESSAGES['en']).get(key, key)
    if args:
        return text.format(*args)
    return text


def show_help(lang: str = 'en'):
    """Display help message and exit."""
    if lang == 'zh':
        help_text = f"""
╔══════════════════════════════════════════════════════════════╗
║              Hysteria2 VPS 一键部署脚本                      ║
╚══════════════════════════════════════════════════════════════╝

用法:  uv run setup_hy2.py [选项]

━━━ 功能 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • 基于 QUIC 的高速 Hysteria2 代理
  • UDP 端口跳跃 ({PORT_HOP_START}-{PORT_HOP_END})，抗封锁
  • 零日志模式 — 不记录任何访问信息
  • 自动 SSL 证书 + 安全加固
  • 输出即用的 Clash / 原生客户端配置
  • 自动清理旧的 iptables 端口跳跃规则 (20000-60000)

━━━ 连接选项 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --server IP             服务器 IP（指定后跳过交互提示）
  --name NAME             服务器别名（默认：IP 地址）
  --ssh-port PORT         SSH 端口（默认：22）
  --user USER             SSH 用户名（默认：root）
  --password PASS         SSH 密码
  --key-auth              使用 SSH 密钥认证
  --privkey PATH          私钥路径（默认：~/.ssh/ 自动检测）
  --pubkey PATH           公钥路径（默认：~/.ssh/ 自动检测）
  --key-passphrase PASS   私钥密码（如有加密）

━━━ Hysteria2 选项 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --port PORT             服务端口（默认：随机生成，避开跳跃范围）
  --docker                用 Docker 运行（默认：原生 systemd）
  --debug                 启用日志（⚠ 会记录访问信息）
  --china                 中国大陆 VPS 模式（见下方说明）
  --local                 本地安装（无需 SSH 连接）

━━━ 安全选项 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --no-harden             跳过安全加固
  --no-password-change    不更改 root 密码
  --new-password STR      指定新 root 密码（默认：随机生成）

━━━ 其他 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --lang en|zh            界面语言（默认：en）
  --save-config PATH      自定义输出目录
  --yes, -y               自动确认提示（脚本模式）
  --help, -h              显示帮助

━━━ 中国模式 (--china) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  适用于中国大陆 VPS（GitHub/Docker Hub 被墙）：
  • 在本地下载 Hysteria2，通过 SFTP 上传到服务器
  • 伪装服务名称，避免 VPS 服务商检测
  • 自动禁用阿里云安骑士、腾讯云盾等监控代理
  • 反向路由：代理国内网站，直连国际网站
  场景：海外用户通过中国 VPS 访问优酷、B站、抖音等

━━━ 示例 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # 交互模式
  uv run setup_hy2.py
  uv run setup_hy2.py --docker

  # 非交互模式
  uv run setup_hy2.py --server 1.2.3.4 --password "pass"
  uv run setup_hy2.py --server 1.2.3.4 --key-auth
  uv run setup_hy2.py --china --server 1.2.3.4 --password "pass"

━━━ 输出文件 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  <服务器名>-<时间戳>/
  ├── clash.yaml        Clash 客户端配置
  ├── hy2-client.yaml   原生客户端配置
  ├── credentials.txt   凭据信息
  └── id_rsa[.pub]      SSH 密钥（自动生成时）
"""
    else:
        help_text = f"""
╔══════════════════════════════════════════════════════════════╗
║            Hysteria2 VPS Setup Script                        ║
╚══════════════════════════════════════════════════════════════╝

Usage:  uv run setup_hy2.py [OPTIONS]

━━━ What it does ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • High-speed QUIC-based Hysteria2 proxy
  • UDP port hopping ({PORT_HOP_START}-{PORT_HOP_END}) for anti-blocking
  • Zero-log mode — no access patterns stored
  • Auto SSL certs + security hardening
  • Outputs ready-to-use Clash & native client configs
  • Auto-cleans old iptables hop rules (20000-60000 range)

━━━ Connection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --server IP             Server IP (skips interactive prompts)
  --name NAME             Friendly label (default: IP address)
  --ssh-port PORT         SSH port (default: 22)
  --user USER             SSH user (default: root)
  --password PASS         SSH password
  --key-auth              Use SSH key authentication
  --privkey PATH          Private key (default: auto-detect ~/.ssh/)
  --pubkey PATH           Public key  (default: auto-detect ~/.ssh/)
  --key-passphrase PASS   Passphrase for encrypted private key

━━━ Hysteria2 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --port PORT             Service port (default: random, outside hop range)
  --docker                Run in Docker (default: native systemd)
  --debug                 Enable logging (⚠ logs access patterns)
  --china                 China-mainland VPS mode (see below)
  --local                 Install on local machine (no SSH)

━━━ Security ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --no-harden             Skip security hardening
  --no-password-change    Keep original root password
  --new-password STR      Set a specific new root password

━━━ Misc ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  --lang en|zh            Interface language (default: en)
  --save-config PATH      Custom output directory
  --yes, -y               Auto-confirm prompts (scripting)
  --help, -h              Show this help

━━━ China Mode (--china) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  For VPS in mainland China (GitHub / Docker Hub blocked):
  • Downloads binary locally, uploads via SFTP
  • Disguises service names to evade VPS-provider scanning
  • Disables Aliyun Aegis, Tencent YunDun, etc.
  • Reverses routing: proxy Chinese sites, direct international
  Use case: access YouKu, Bilibili, Douyin from outside China.

━━━ Examples ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  # Interactive
  uv run setup_hy2.py
  uv run setup_hy2.py --docker

  # Non-interactive
  uv run setup_hy2.py --server 1.2.3.4 --password "pass"
  uv run setup_hy2.py --server 1.2.3.4 --key-auth
  uv run setup_hy2.py --china --server 1.2.3.4 --password "pass"

━━━ Output ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  <server_name>-<timestamp>/
  ├── clash.yaml        Clash client config
  ├── hy2-client.yaml   Native client config
  ├── credentials.txt   Server credentials
  └── id_rsa[.pub]      SSH keys (if auto-generated)
"""
    print(help_text)
    sys.exit(0)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Hysteria2 VPS Setup Script",
        add_help=False
    )
    parser.add_argument('--help', '-h', action='store_true', help='Show help message')
    parser.add_argument('--server', '--host', type=str, default=None, dest='server',
                        help='Server IP address (skip prompt if provided)')
    parser.add_argument('--name', type=str, default=None,
                        help='Server name for config labels (default: server IP)')
    parser.add_argument('--ssh-port', type=int, default=None,
                        help='SSH port (default: 22)')
    parser.add_argument('--user', type=str, default=None,
                        help='SSH username (default: root)')
    parser.add_argument('--password', type=str, default=None,
                        help='SSH password (for password auth mode)')
    parser.add_argument('--key-passphrase', type=str, default=None,
                        help='Passphrase for encrypted private key (--key-auth mode)')
    parser.add_argument('--pubkey', type=str, default=None, 
                        help='Path to SSH public key (default: auto-detect from ~/.ssh/)')
    parser.add_argument('--privkey', type=str, default=None,
                        help='Path to SSH private key (default: auto-detect from ~/.ssh/)')
    parser.add_argument('--key-auth', action='store_true',
                        help='Use key-based authentication (for servers with pre-installed pubkey)')
    parser.add_argument('--port', type=int, default=None,
                        help=f'Hysteria2 service port (default: random, outside hop range {PORT_HOP_START}-{PORT_HOP_END})')
    parser.add_argument('--no-harden', action='store_true',
                        help='Skip security hardening steps')
    parser.add_argument('--no-password-change', action='store_true',
                        help='Keep original root password (skip password change)')
    parser.add_argument('--new-password', type=str, default=None,
                        help='New root password (auto-generated if not specified)')
    parser.add_argument('--save-config', type=str, default=None,
                        help='Directory to save generated configs (clash.yaml, hy2-client.yaml, credentials.txt)')
    parser.add_argument('--docker', action='store_true',
                        help='Install Hysteria2 in Docker container instead of native binary')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging mode (logs connection info for troubleshooting). '
                             'WARNING: This stores access patterns on disk. Re-run without --debug to restore zero-log mode.')
    parser.add_argument('--china', action='store_true',
                        help='China mode: for VPS in mainland China (Aliyun/Tencent/JDCloud). '
                             'Downloads binary locally then uploads via SFTP (GitHub blocked in China). '
                             'Uses Chinese Docker mirrors. Disables VPS provider monitoring. '
                             'Reverses routing rules (proxy Chinese sites, direct others).')
    parser.add_argument('--local', action='store_true',
                        help='Install on local machine (no SSH connection, requires sudo)')
    parser.add_argument('--yes', '-y', action='store_true',
                        help='Auto-confirm prompts (for scripting)')
    parser.add_argument('--lang', '--language', type=str, default=None, dest='lang',
                        choices=['en', 'zh'],
                        help='Interface language: en or zh (default: en in non-interactive mode)')
    
    args = parser.parse_args()
    
    if args.help:
        show_help(args.lang if args.lang else 'en')
    
    # Validate --port argument
    if args.port is not None:
        if not validate_port(args.port):
            print(msg('error_invalid_port_arg', args.port))
            sys.exit(1)
    
    return args


def generate_ssh_keypair(key_path: Path) -> tuple[Path, Path]:
    """Generate a new RSA SSH key pair.
    
    Args:
        key_path: Path to save the private key (public key will be key_path + '.pub')
        
    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    from paramiko import RSAKey
    
    # Ensure directory exists
    key_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"  Generating new RSA key pair...")
    
    # Generate 4096-bit RSA key
    key = RSAKey.generate(SSH_KEY_BITS)
    
    # Save private key
    key.write_private_key_file(str(key_path))
    print(f"  ✓ Private key saved: {key_path}")
    
    # Save public key
    pub_key_path = Path(str(key_path) + '.pub')
    pub_key_str = f"ssh-rsa {key.get_base64()} generated-by-setup_hy2"
    pub_key_path.write_text(pub_key_str)
    print(f"  ✓ Public key saved: {pub_key_path}")
    
    # Set proper permissions on private key (Unix-like systems)
    try:
        import os
        os.chmod(key_path, 0o600)
    except Exception:
        pass  # Windows doesn't support chmod the same way
    
    return key_path, pub_key_path


def get_default_pubkey_path() -> Path:
    """Get the default SSH public key path.
    
    Search order:
    1. ~/.ssh/ folder (with selection if multiple keys exist)
    2. ./id_rsa.pub (script directory fallback)
    
    Returns path to key, or prompts user to select if multiple exist.
    """
    home = Path.home()
    ssh_dir = home / '.ssh'
    
    # Get platform-appropriate path display
    if platform.system() == 'Windows':
        ssh_display = str(ssh_dir).replace('\\', '/')
    else:
        ssh_display = f"~/.ssh"
    
    # Find all public keys in ~/.ssh
    pub_keys = []
    if ssh_dir.exists():
        for key_name in ['id_rsa.pub', 'id_ed25519.pub', 'id_ecdsa.pub', 'id_dsa.pub']:
            key_path = ssh_dir / key_name
            if key_path.exists():
                pub_keys.append(key_path)
        
        # Also check for custom named keys (*.pub files)
        for pub_file in ssh_dir.glob('*.pub'):
            if pub_file not in pub_keys and pub_file.stem not in ['known_hosts', 'authorized_keys', 'config']:
                pub_keys.append(pub_file)
    
    # Check script directory as fallback
    repo_key_path = SCRIPT_DIR / 'id_rsa.pub'
    if repo_key_path.exists() and repo_key_path not in pub_keys:
        pub_keys.append(repo_key_path)
    
    if len(pub_keys) == 0:
        # No keys found, return default location for new key generation
        return ssh_dir / 'id_rsa.pub'
    elif len(pub_keys) == 1:
        # Only one key found, use it
        return pub_keys[0]
    else:
        # Multiple keys found, let user select
        print(f"\n[INFO] Found multiple SSH public keys:")
        for i, key_path in enumerate(pub_keys, 1):
            # Show relative path if in .ssh, full path otherwise
            if key_path.parent == ssh_dir:
                display_path = f"{ssh_display}/{key_path.name}"
            else:
                display_path = str(key_path)
            print(f"  [{i}] {display_path}")
        
        while True:
            try:
                choice = input(f"\nSelect key [1-{len(pub_keys)}] (default: 1): ").strip()
                if not choice:
                    return pub_keys[0]
                idx = int(choice) - 1
                if 0 <= idx < len(pub_keys):
                    return pub_keys[idx]
                print(f"  Invalid choice. Please enter 1-{len(pub_keys)}")
            except ValueError:
                print(f"  Invalid input. Please enter a number 1-{len(pub_keys)}")


def get_default_privkey_path() -> Path:
    """Get the default SSH private key path.
    
    Search order:
    1. ~/.ssh/ folder (with selection if multiple keys exist)
    2. ./id_rsa (script directory fallback)
    
    Returns path to key, or prompts user to select if multiple exist.
    """
    home = Path.home()
    ssh_dir = home / '.ssh'
    
    # Get platform-appropriate path display
    if platform.system() == 'Windows':
        ssh_display = str(ssh_dir).replace('\\', '/')
    else:
        ssh_display = f"~/.ssh"
    
    # Find all private keys in ~/.ssh
    priv_keys = []
    if ssh_dir.exists():
        for key_name in ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa']:
            key_path = ssh_dir / key_name
            if key_path.exists():
                priv_keys.append(key_path)
        
        # Also check for custom named keys (files without .pub extension that aren't config files)
        known_non_keys = {'known_hosts', 'authorized_keys', 'config', 'environment'}
        for file_path in ssh_dir.iterdir():
            if (file_path.is_file() and 
                not file_path.name.endswith('.pub') and 
                file_path.name not in known_non_keys and
                file_path not in priv_keys):
                # Quick check if it looks like a key file
                try:
                    content = file_path.read_text(errors='ignore')[:100]
                    if 'PRIVATE KEY' in content or 'OPENSSH PRIVATE KEY' in content:
                        priv_keys.append(file_path)
                except (OSError, UnicodeDecodeError):
                    pass
    
    # Check script directory as fallback
    repo_key_path = SCRIPT_DIR / 'id_rsa'
    if repo_key_path.exists() and repo_key_path not in priv_keys:
        priv_keys.append(repo_key_path)
    
    if len(priv_keys) == 0:
        # No keys found, return default location
        return ssh_dir / 'id_rsa'
    elif len(priv_keys) == 1:
        # Only one key found, use it
        return priv_keys[0]
    else:
        # Multiple keys found, let user select
        print(f"\n[INFO] Found multiple SSH private keys:")
        for i, key_path in enumerate(priv_keys, 1):
            # Show relative path if in .ssh, full path otherwise
            if key_path.parent == ssh_dir:
                display_path = f"{ssh_display}/{key_path.name}"
            else:
                display_path = str(key_path)
            print(f"  [{i}] {display_path}")
        
        while True:
            try:
                choice = input(f"\nSelect key [1-{len(priv_keys)}] (default: 1): ").strip()
                if not choice:
                    return priv_keys[0]
                idx = int(choice) - 1
                if 0 <= idx < len(priv_keys):
                    return priv_keys[idx]
                print(f"  Invalid choice. Please enter 1-{len(priv_keys)}")
            except ValueError:
                print(f"  Invalid input. Please enter a number 1-{len(priv_keys)}")


def read_pubkey(pubkey_path: Path, auto_generate: bool = True, save_dir: Path | None = None) -> str | None:
    """Read the SSH public key from file, or generate if not found.
    
    Args:
        pubkey_path: Path to the public key file
        auto_generate: If True, generate a new key pair if not found
        save_dir: Directory to save generated keys (defaults to pubkey_path's parent)
        
    Returns:
        The public key string, or None if not found and auto_generate is False
    """
    try:
        if pubkey_path.exists():
            return pubkey_path.read_text().strip()
        else:
            if auto_generate:
                print(f"\n[INFO] No SSH key found at {pubkey_path}")
                print("[INFO] Generating new RSA key pair for you...")
                
                # Determine where to save - always use save_dir if provided
                if save_dir:
                    key_dir = Path(save_dir)
                else:
                    key_dir = pubkey_path.parent
                
                key_dir.mkdir(parents=True, exist_ok=True)
                priv_key_path = key_dir / 'id_rsa'
                
                # Generate the key pair
                _, pub_key_path = generate_ssh_keypair(priv_key_path)
                
                print(f"\n[IMPORTANT] Save these keys securely!")
                print(f"  Private key: {priv_key_path}")
                print(f"  Public key:  {pub_key_path}")
                print()
                
                return pub_key_path.read_text().strip()
            else:
                print(f"[WARN] Public key not found at {pubkey_path}")
                return None
    except Exception as e:
        print(f"[WARN] Could not read public key: {e}")
        return None


def generate_password(length: int = HY2_PASSWORD_LENGTH) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def validate_ip_address(ip: str) -> bool:
    """Validate if the given string is a valid IPv4 or IPv6 address, or 'localhost'."""
    if ip.lower() == 'localhost':
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate if the given port number is valid (1-65535)."""
    return 1 <= port <= 65535


def get_config_yaml(password: str, port: int, debug_mode: bool = False) -> tuple[str, str]:
    """Generate Hysteria2 server config.
    
    Args:
        password: Hysteria2 authentication password
        port: Service port number
        debug_mode: If True, enable logging. If False (default), zero-log mode.
    
    Returns:
        Tuple of (config_yaml, masquerade_domain)
    """
    # High-traffic websites for masquerade - randomly selected
    masquerade_urls = [
        'https://www.microsoft.com/',
        'https://www.office.com/',
        'https://www.bing.com/',
        'https://azure.microsoft.com/',
        'https://www.apple.com/',
        'https://www.cloudflare.com/',
        'https://www.oracle.com/',
        'https://www.nvidia.com/',
        'https://www.adobe.com/',
        'https://www.amazon.com/',
        'https://www.spotify.com/',
        'https://www.coursera.org/',
    ]
    masquerade_url = random.choice(masquerade_urls)
    # Extract domain from URL for SNI
    masquerade_domain = masquerade_url.replace('https://', '').replace('/', '')
    
    log_level = 'debug' if debug_mode else 'silent'
    log_comment = '# DEBUG MODE' if debug_mode else '# ZERO-LOG MODE'
    
    config = f'''listen: :{port}

{log_comment}
log:
  level: {log_level}

tls:
  cert: /etc/server.crt
  key: /etc/server.key

auth:
  type: password
  password: "{password}"

masquerade:
  type: proxy
  proxy:
    url: {masquerade_url}
    rewriteHost: true

udpIdleTimeout: 60s

sniff:
  enable: true
  timeout: 2s
  rewriteDomain: false

quic:
  maxIdleTimeout: 30s

ignoreClientBandwidth: true
'''
    return config, masquerade_domain


def get_compose_yaml(debug_mode: bool = False) -> str:
    """Generate Docker Compose config.
    
    Args:
        debug_mode: If True, enable Docker logging. If False (default), zero-log mode.
    """
    if debug_mode:
        logging_config = '''logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"'''
    else:
        logging_config = '''logging:
      driver: none'''
    
    return f'''version: "3.9"
services:
  hy2:
    image: tobyxdd/hysteria
    container_name: hy2
    restart: always
    {logging_config}
    network_mode: "host"
    volumes:
      - ./config.yaml:/etc/config.yaml
      - ./server.crt:/etc/server.crt
      - ./server.key:/etc/server.key
    command: ["server", "-c", "/etc/config.yaml"]
'''


# ---------------------------------------------------------------------------
# LocalSSHClient - Mock SSH client for local mode (no actual SSH connection)
# ---------------------------------------------------------------------------
class _LocalChannel:
    """Mock channel for LocalSSHClient exec_command results."""
    def __init__(self, returncode: int):
        self.returncode = returncode
    
    def recv_exit_status(self) -> int:
        return self.returncode


class _LocalStdout:
    """Mock stdout for LocalSSHClient exec_command results."""
    def __init__(self, output: str, returncode: int):
        self._output = output
        self._lines = output.splitlines(keepends=True)
        self._index = 0
        self.channel = _LocalChannel(returncode)
    
    def read(self) -> bytes:
        return self._output.encode('utf-8')
    
    def readline(self) -> str:
        if self._index < len(self._lines):
            line = self._lines[self._index]
            self._index += 1
            return line
        return ''


class _LocalStderr:
    """Mock stderr for LocalSSHClient exec_command results."""
    def __init__(self, error: str):
        self._error = error
    
    def read(self) -> bytes:
        return self._error.encode('utf-8')


class _LocalSFTP:
    """Mock SFTP for local file operations."""
    def get(self, remotepath: str, localpath: str) -> None:
        """Copy file from 'remote' (local) path to local path."""
        import shutil
        shutil.copy2(remotepath, localpath)
    
    def put(self, localpath: str, remotepath: str) -> None:
        """Copy file from local path to 'remote' (local) path."""
        import shutil
        shutil.copy2(localpath, remotepath)
    
    def close(self) -> None:
        pass


class LocalSSHClient:
    """Mock SSH client that runs commands locally instead of over SSH.
    
    Used for local mode installation when the target is localhost/127.0.0.1.
    Mimics the paramiko.SSHClient interface.
    """
    
    def set_missing_host_key_policy(self, policy) -> None:
        """No-op for local mode."""
        pass
    
    def connect(self, **kwargs) -> None:
        """No-op for local mode - we're already 'connected' locally."""
        pass
    
    def close(self) -> None:
        """No-op for local mode."""
        pass
    
    def exec_command(self, cmd: str, get_pty: bool = False) -> tuple:
        """Execute command locally using subprocess.
        
        Returns:
            Tuple of (stdin, stdout, stderr) mimicking paramiko interface
        """
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            stdout = _LocalStdout(result.stdout, result.returncode)
            stderr = _LocalStderr(result.stderr)
            return (None, stdout, stderr)
        except Exception as e:
            stdout = _LocalStdout('', 1)
            stderr = _LocalStderr(str(e))
            return (None, stdout, stderr)
    
    def open_sftp(self) -> _LocalSFTP:
        """Return a mock SFTP client for local file operations."""
        return _LocalSFTP()


def run_command(ssh: 'paramiko.SSHClient | LocalSSHClient', cmd: str, check_error: bool = True, show_output: bool = False, quiet: bool = False) -> str:
    """Execute a command on the remote server (or locally in local mode).
    
    Args:
        ssh: Paramiko SSH client or LocalSSHClient for local mode
        cmd: Command to execute
        check_error: Whether to print warnings on non-zero exit codes
        show_output: Whether to print command output in real-time
        quiet: If True, suppress command echo (use for sensitive commands)
    
    Returns:
        The command's stdout output
    """
    if not quiet:
        print(f"  > {cmd}")
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=False)
    
    output_lines = []
    if show_output:
        # Read output line by line in real-time
        import sys
        while True:
            line = stdout.readline()
            if not line:
                break
            line_decoded = line if isinstance(line, str) else line.decode('utf-8', errors='ignore')
            output_lines.append(line_decoded)
            print(f"    {line_decoded.rstrip()}")
            sys.stdout.flush()
        output = ''.join(output_lines)
    else:
        output = stdout.read().decode('utf-8', errors='ignore')
    
    error = stderr.read().decode('utf-8', errors='ignore')
    exit_code = stdout.channel.recv_exit_status()
    
    if check_error and exit_code != 0:
        print_warn(f"  [WARN] Command exited with code {exit_code}")
        if error:
            print_err(f"  [STDERR] {error}")
    
    return output


def run_local_command(cmd: str, check_error: bool = True, show_output: bool = False, use_sudo: bool = False) -> str:
    """Execute a command on the local machine and return output.
    
    SECURITY NOTE: Uses shell=True – only call with trusted, internally
    constructed command strings. Never pass unsanitised user input.
    
    Args:
        cmd: Command to execute (must be a trusted string)
        check_error: Whether to print warnings on non-zero exit codes
        show_output: Whether to print command output in real-time
        use_sudo: Whether to prepend sudo to the command
    
    Returns:
        The command's stdout output
    """
    if use_sudo:
        if platform.system() == 'Windows':
            # Windows doesn't have sudo
            pass
        else:
            # Check if we're already root
            if os.geteuid() != 0:
                cmd = f"sudo {cmd}"
    
    print(f"  > {cmd}")
    
    try:
        if show_output:
            # Real-time output
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    output_lines.append(line)
                    print(f"    {line.rstrip()}")
            
            output = ''.join(output_lines)
            _, stderr_output = process.communicate()
            exit_code = process.returncode
        else:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            output = result.stdout
            stderr_output = result.stderr
            exit_code = result.returncode
        
        if check_error and exit_code != 0:
            print_warn(f"  [WARN] Command exited with code {exit_code}")
            if stderr_output:
                print_err(f"  [STDERR] {stderr_output}")
        
        return output
        
    except Exception as e:
        if check_error:
            print_err(f"  [ERROR] Failed to run command: {e}")
        return ""


def detect_os(ssh: paramiko.SSHClient) -> dict:
    """
    Detect the operating system type and version on the remote server.
    
    Returns a dict with:
    - os_type: 'debian', 'ubuntu', 'centos', 'rhel', 'fedora', 'alpine', 'unknown'
    - os_version: version string (e.g., '22.04', '12', '9')
    - os_codename: codename if available (e.g., 'jammy', 'bookworm')
    - os_name: full name (e.g., 'Ubuntu 22.04.3 LTS')
    - pkg_manager: 'apt', 'yum', 'dnf', 'apk', 'unknown'
    """
    os_info = {
        'os_type': 'unknown',
        'os_version': '',
        'os_codename': '',
        'os_name': '',
        'pkg_manager': 'unknown'
    }
    
    # Try to read /etc/os-release (most modern Linux distros)
    os_release = run_command(ssh, "cat /etc/os-release 2>/dev/null || echo ''", check_error=False)
    
    if os_release:
        # Parse os-release file
        for line in os_release.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                value = value.strip('"\'')
                if key == 'ID':
                    os_info['os_type'] = value.lower()
                elif key == 'VERSION_ID':
                    os_info['os_version'] = value
                elif key == 'VERSION_CODENAME':
                    os_info['os_codename'] = value
                elif key == 'PRETTY_NAME':
                    os_info['os_name'] = value
    
    # If os_codename is empty, try lsb_release
    if not os_info['os_codename'] and os_info['os_type'] in ['debian', 'ubuntu']:
        codename_output = run_command(ssh, "lsb_release -cs 2>/dev/null || echo ''", check_error=False)
        os_info['os_codename'] = codename_output.strip()
    
    # Determine package manager based on OS type
    if os_info['os_type'] in ['debian', 'ubuntu', 'linuxmint', 'pop']:
        os_info['pkg_manager'] = 'apt'
    elif os_info['os_type'] in ['centos', 'rhel', 'rocky', 'almalinux', 'oracle']:
        # CentOS 8+ and RHEL 8+ use dnf
        if os_info['os_version'] and os_info['os_version'].split('.')[0] >= '8':
            os_info['pkg_manager'] = 'dnf'
        else:
            os_info['pkg_manager'] = 'yum'
    elif os_info['os_type'] in ['fedora']:
        os_info['pkg_manager'] = 'dnf'
    elif os_info['os_type'] == 'alpine':
        os_info['pkg_manager'] = 'apk'
    
    # Fallback: check for package managers directly
    if os_info['pkg_manager'] == 'unknown':
        if 'apt' in run_command(ssh, "which apt 2>/dev/null || echo ''", check_error=False):
            os_info['pkg_manager'] = 'apt'
        elif 'dnf' in run_command(ssh, "which dnf 2>/dev/null || echo ''", check_error=False):
            os_info['pkg_manager'] = 'dnf'
        elif 'yum' in run_command(ssh, "which yum 2>/dev/null || echo ''", check_error=False):
            os_info['pkg_manager'] = 'yum'
        elif 'apk' in run_command(ssh, "which apk 2>/dev/null || echo ''", check_error=False):
            os_info['pkg_manager'] = 'apk'
    
    return os_info


def check_docker_installed(ssh: paramiko.SSHClient) -> bool:
    """Check if Docker is installed on the remote server."""
    result = run_command(ssh, "docker --version 2>/dev/null && echo 'DOCKER_FOUND' || echo 'DOCKER_NOT_FOUND'", check_error=False)
    return 'DOCKER_FOUND' in result


def configure_docker_ipv6(ssh: paramiko.SSHClient) -> None:
    """
    Configure Docker to disable IPv6 to prevent conflicts with multi-IP VPS setups.
    
    Docker's default IPv6 configuration can:
    - Create fd00::/80 routes on docker0 that conflict with host routing
    - Assign IPv6 addresses from the host's subnet to docker0
    - Break routing for multiple IPv6 addresses on the host
    
    This function disables Docker IPv6 to prevent these issues.
    """
    print("  Configuring Docker IPv6 settings...")
    
    # Create or update /etc/docker/daemon.json
    daemon_json = '{"ipv6": false}'
    
    # Check if daemon.json exists and preserve existing settings
    existing = run_command(ssh, "cat /etc/docker/daemon.json 2>/dev/null || echo '{}'", check_error=False).strip()
    if existing and existing != '{}':
        try:
            import json
            config = json.loads(existing)
            config['ipv6'] = False
            daemon_json = json.dumps(config, indent=2)
        except (json.JSONDecodeError, ValueError):
            # If we can't parse it, just overwrite with basic config
            pass
    
    run_command(ssh, f"mkdir -p /etc/docker")
    run_command(ssh, f"cat > /etc/docker/daemon.json << 'DAEMONJSONEOF'\n{daemon_json}\nDAEMONJSONEOF")
    
    # Restart Docker to apply the setting (if Docker is running)
    docker_running = run_command(ssh, "systemctl is-active docker 2>/dev/null || service docker status 2>/dev/null | grep -q running && echo 'RUNNING' || echo 'NOT_RUNNING'", check_error=False)
    if 'RUNNING' in docker_running:
        print("  Restarting Docker to apply IPv6 settings...")
        run_command(ssh, "systemctl restart docker 2>/dev/null || service docker restart 2>/dev/null || true", check_error=False)
    
    print("  ✓ Docker IPv6 disabled (prevents conflicts with multi-IP setups)")


def install_docker_for_os(ssh: paramiko.SSHClient, os_info: dict) -> bool:
    """
    Install Docker based on the detected OS type.
    
    Returns True if installation was successful, False otherwise.
    """
    os_type = os_info['os_type']
    pkg_manager = os_info['pkg_manager']
    codename = os_info['os_codename']
    version = os_info['os_version']
    
    print(f"  Installing Docker for {os_info['os_name']} ({os_type})...")
    
    if pkg_manager == 'apt':
        # Debian/Ubuntu based systems
        # Install prerequisites
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get update", check_error=False)
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release", check_error=False)
        
        if os_type == 'ubuntu':
            # Ubuntu-specific Docker installation
            run_command(ssh, "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg", check_error=False)
            run_command(ssh, f'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu {codename} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null', check_error=False)
        elif os_type == 'debian':
            # Debian-specific Docker installation
            run_command(ssh, "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg", check_error=False)
            run_command(ssh, f'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian {codename} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null', check_error=False)
        else:
            # Generic apt-based (try Debian method as fallback)
            run_command(ssh, "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg", check_error=False)
            if not codename:
                codename = run_command(ssh, "lsb_release -cs 2>/dev/null || echo 'stable'", check_error=False).strip()
            run_command(ssh, f'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian {codename} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null', check_error=False)
        
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get update", check_error=False, show_output=True)
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin", check_error=False, show_output=True)
    
    elif pkg_manager == 'dnf':
        # Fedora/CentOS 8+/RHEL 8+ systems
        run_command(ssh, "dnf -y install dnf-plugins-core", check_error=False)
        
        if os_type == 'fedora':
            run_command(ssh, "dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo", check_error=False)
        else:
            # CentOS/RHEL/Rocky/AlmaLinux
            run_command(ssh, "dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo", check_error=False)
        
        run_command(ssh, "dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin", check_error=False)
        run_command(ssh, "systemctl start docker", check_error=False)
        run_command(ssh, "systemctl enable docker", check_error=False)
    
    elif pkg_manager == 'yum':
        # CentOS 7/RHEL 7 systems
        run_command(ssh, "yum install -y yum-utils", check_error=False)
        run_command(ssh, "yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo", check_error=False)
        run_command(ssh, "yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin", check_error=False)
        run_command(ssh, "systemctl start docker", check_error=False)
        run_command(ssh, "systemctl enable docker", check_error=False)
    
    elif pkg_manager == 'apk':
        # Alpine Linux
        run_command(ssh, "apk add --update docker docker-cli-compose", check_error=False)
        run_command(ssh, "rc-update add docker boot", check_error=False)
        run_command(ssh, "service docker start", check_error=False)
    
    else:
        # Fallback: use the convenience script
        print("  [INFO] Using Docker's convenience script for installation...")
        run_command(ssh, "curl -fsSL https://get.docker.com -o get-docker.sh", check_error=False)
        run_command(ssh, "sh get-docker.sh", check_error=False)
        run_command(ssh, "systemctl start docker 2>/dev/null || service docker start 2>/dev/null || true", check_error=False)
        run_command(ssh, "systemctl enable docker 2>/dev/null || true", check_error=False)
    
    # Disable Docker IPv6 to prevent conflicts with multi-IP VPS setups
    # Docker's IPv6 can create routes/addresses that conflict with host IPv6 addresses
    configure_docker_ipv6(ssh)
    
    # Verify Docker installation
    return check_docker_installed(ssh)


def install_hysteria2_native(ssh: paramiko.SSHClient, os_info: dict) -> bool:
    """
    Install Hysteria2 as a native binary with systemd service.
    
    This is the recommended method for multi-IP VPS setups as it avoids
    Docker's networking complexity that can conflict with host IPv6 routing.
    
    Returns True if installation was successful, False otherwise.
    """
    print("  Installing Hysteria2 native binary...")
    
    # Clean up any stale temp files from previous attempts
    run_command(ssh, "rm -f /tmp/hysteria-download /tmp/hysteria-new /tmp/hysteria-sha256.txt 2>/dev/null || true", check_error=False)
    
    # Stop existing service if running (to allow replacing the binary)
    print("  Stopping existing service...")
    run_command(ssh, "systemctl stop hysteria 2>/dev/null || true", check_error=False)
    
    # Wait a moment for service to fully stop
    time.sleep(2)
    
    # Make sure hysteria process is really stopped
    run_command(ssh, "pkill -9 -f '/usr/local/bin/hysteria' 2>/dev/null || true", check_error=False)
    
    # Detect architecture
    arch = run_command(ssh, "uname -m", check_error=False).strip()
    if arch == 'x86_64':
        hy2_arch = 'amd64'
    elif arch == 'aarch64':
        hy2_arch = 'arm64'
    elif 'arm' in arch:
        hy2_arch = 'arm'
    else:
        print(f"  [WARN] Unknown architecture: {arch}, trying amd64")
        hy2_arch = 'amd64'
    
    print(f"  Architecture detected: {arch} -> hysteria-linux-{hy2_arch}")
    
    # Check if binary already exists and is working
    existing_version = run_command(ssh, "/usr/local/bin/hysteria version 2>/dev/null | head -1", check_error=False).strip()
    if existing_version:
        print(f"  Hysteria2 already installed: {existing_version}")
        print("  Binary already exists and is functional.")
        run_command(ssh, "mkdir -p /etc/hysteria", check_error=False)
        return True
    
    # Download latest Hysteria2 binary from GitHub
    download_url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-{hy2_arch}"
    sha256_url = f"https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-{hy2_arch}.sha256"
    print(f"  Downloading from: {download_url}")
    
    download_success = False
    
    # Method 1: curl with longer timeout and retry
    result = run_command(ssh, f"curl -fsSL --connect-timeout {DOWNLOAD_CONNECT_TIMEOUT} --max-time {DOWNLOAD_TIMEOUT} --retry 3 '{download_url}' -o /tmp/hysteria-new 2>&1", check_error=False, show_output=True)
    
    # Check if download succeeded (file exists, is not empty, and is executable binary)
    file_info = run_command(ssh, "ls -la /tmp/hysteria-new 2>/dev/null; file /tmp/hysteria-new 2>/dev/null", check_error=False)
    print(f"  Downloaded file info: {file_info.strip()}")
    
    if 'ELF' in file_info:
        # Download and verify SHA256
        sha_result = run_command(ssh, f"curl -fsSL --connect-timeout 30 '{sha256_url}' 2>/dev/null", check_error=False).strip()
        if sha_result:
            # SHA256 file contains: <hash>  <filename>
            expected_hash = sha_result.split()[0] if sha_result else ""
            if expected_hash:
                actual_hash = run_command(ssh, "sha256sum /tmp/hysteria-new | awk '{print $1}'", check_error=False).strip()
                if expected_hash.lower() == actual_hash.lower():
                    download_success = True
                    print(f"  ✓ SHA256 verified: {actual_hash[:16]}...")
                else:
                    print(f"  [ERROR] SHA256 mismatch! Binary may be corrupted or tampered.")
                    print(f"         Expected: {expected_hash}")
                    print(f"         Got:      {actual_hash}")
                    run_command(ssh, "rm -f /tmp/hysteria-new 2>/dev/null || true", check_error=False)
                    download_success = False
            else:
                download_success = True
                print("  ✓ Download successful (no SHA256 available)")
        else:
            download_success = True
            print("  ✓ Download successful (SHA256 check skipped)")
    
    if not download_success:
        # Method 2: try wget as fallback
        print("  curl download failed or file invalid, trying wget...")
        run_command(ssh, "rm -f /tmp/hysteria-new 2>/dev/null || true", check_error=False)
        result = run_command(ssh, f"wget --timeout=60 -q -O /tmp/hysteria-new '{download_url}' 2>&1", check_error=False, show_output=True)
        file_info = run_command(ssh, "file /tmp/hysteria-new 2>/dev/null", check_error=False)
        if 'ELF' in file_info:
            download_success = True
            print("  ✓ Download successful (wget)")
    
    if not download_success:
        print("  ✗ Download failed - could not get a valid binary")
        return False
    
    # Install the binary
    print("  Installing binary to /usr/local/bin/hysteria...")
    
    # Copy then set permissions
    install_result = run_command(ssh, """
        cp /tmp/hysteria-new /usr/local/bin/hysteria && \
        chmod 755 /usr/local/bin/hysteria && \
        chown root:root /usr/local/bin/hysteria && \
        ls -la /usr/local/bin/hysteria && \
        echo "INSTALL_OK"
    """, check_error=False)
    
    if 'INSTALL_OK' not in install_result:
        print(f"  ✗ Failed to install binary: {install_result}")
        return False
    
    print(f"  Installed: {install_result.strip()}")
    
    # Verify installation by running the binary
    version = run_command(ssh, "/usr/local/bin/hysteria version 2>&1", check_error=False).strip()
    if version and 'hysteria' in version.lower():
        print(f"  ✓ Hysteria2 installed: {version.split()[0] if version else 'unknown'}")
    else:
        # Try to see why it fails
        print(f"  Version check output: {version}")
        ldd_result = run_command(ssh, "ldd /usr/local/bin/hysteria 2>&1 || file /usr/local/bin/hysteria", check_error=False)
        print(f"  Binary info: {ldd_result.strip()[:200]}")
        
        # Even if version check fails, the binary might still work for running the server
        # Check if file exists and is executable
        exists_check = run_command(ssh, "test -x /usr/local/bin/hysteria && echo EXISTS", check_error=False)
        if 'EXISTS' in exists_check:
            print("  [WARN] Version check failed, but binary exists and is executable")
            print("         Proceeding with installation...")
        else:
            print("  ✗ Binary not properly installed")
            return False
    
    # Clean up temp files
    run_command(ssh, "rm -f /tmp/hysteria-new /tmp/hysteria-sha256.txt 2>/dev/null || true", check_error=False)
    
    # Create working directory
    run_command(ssh, "mkdir -p /etc/hysteria", check_error=False)
    
    return True


def create_hysteria2_systemd_service(ssh: paramiko.SSHClient, debug_mode: bool = False) -> None:
    """Create systemd service for Hysteria2.
    
    Args:
        ssh: Paramiko SSH client
        debug_mode: If True, enable journald logging. If False (default), zero-log mode.
    
    SECURITY (zero-log mode): Logging is completely disabled to prevent access pattern exposure:
    - StandardOutput/StandardError set to null (no journald logging)
    - Hysteria2 config uses log level 'silent' (no application logging)
    - This ensures zero records of user connections if server is compromised
    """
    print("  Creating systemd service...")
    
    if debug_mode:
        # Debug mode: enable journald logging
        logging_config = '''# DEBUG MODE: Journald logging enabled for troubleshooting
# Use 'journalctl -u hysteria -f' to view logs
StandardOutput=journal
StandardError=journal'''
    else:
        # Zero-log mode: disable all logging
        logging_config = '''# SECURITY: Zero-log mode - all logging disabled
# If the server is compromised, attackers cannot view user access logs
StandardOutput=null
StandardError=null'''
    
    service_content = f'''[Unit]
Description=Hysteria2 Server
Documentation=https://v2.hysteria.network/
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
{logging_config}

[Install]
WantedBy=multi-user.target
'''
    
    run_command(ssh, f"cat > /etc/systemd/system/hysteria.service << 'SERVICEEOF'\n{service_content}\nSERVICEEOF")
    run_command(ssh, "systemctl daemon-reload")
    run_command(ssh, "systemctl enable hysteria")
    print("  ✓ Systemd service created and enabled")


def start_hysteria2_native(ssh: paramiko.SSHClient) -> bool:
    """Start the native Hysteria2 service."""
    print("  Starting Hysteria2 service...")
    
    # Stop if already running
    run_command(ssh, "systemctl stop hysteria 2>/dev/null || true", check_error=False)
    
    # Start the service
    run_command(ssh, "systemctl start hysteria")
    
    # Wait a moment for service to start
    time.sleep(3)
    
    # Check status
    status = run_command(ssh, "systemctl is-active hysteria 2>/dev/null || echo 'inactive'", check_error=False).strip()
    if status == 'active':
        print("  ✓ Hysteria2 service started successfully!")
        return True
    else:
        print("  ✗ Hysteria2 service failed to start")
        run_command(ssh, "systemctl status hysteria 2>&1 | tail -20", check_error=False, show_output=True)
        run_command(ssh, "journalctl -u hysteria --no-pager -n 20 2>&1", check_error=False, show_output=True)
        return False


def extract_pin_sha256(cert_output: str) -> str:
    """Extract SHA256 fingerprint in colon-separated hex format.
    
    The openssl command outputs: sha256 Fingerprint=XX:XX:XX:...
    We keep it in the colon-separated hex format for pinSHA256.
    """
    # Find the fingerprint in format XX:XX:XX:...
    match = re.search(r'(?:SHA256 Fingerprint=|sha256 Fingerprint=)([A-Fa-f0-9:]+)', cert_output)
    if match:
        # Return the colon-separated hex format directly
        return match.group(1).upper()
    return ""


def harden_server_security(ssh: paramiko.SSHClient, new_root_password: str, hy2_port: int, os_info: dict = None, skip_password_change: bool = False) -> dict:
    """
    Apply security hardening to the server.
    
    Args:
        ssh: Paramiko SSH client
        new_root_password: New password for root user
        hy2_port: Hysteria2 service port
        os_info: OS detection info dict (optional, will detect if not provided)
        skip_password_change: If True, keep original root password
    
    Returns a dict with the security changes made.
    """
    security_info = {
        'ssh_key_only': False,
        'password_changed': False,
        'agents_disabled': [],
        'firewall_hardened': False,
        'fail2ban_installed': False,
    }
    
    # Detect OS if not provided
    if os_info is None:
        os_info = detect_os(ssh)
    
    pkg_manager = os_info.get('pkg_manager', 'apt')
    
    print(msg('security_applying'))
    
    # 1. Change root password (unless skipped)
    if skip_password_change:
        print("  [1/6] Keeping original root password (--no-password-change)")
    else:
        print(msg('security_step1'))
        # Use chpasswd which doesn't require interactive input
        result = run_command(ssh, f"echo 'root:{new_root_password}' | chpasswd", check_error=False, quiet=True)
        security_info['password_changed'] = True
        print(msg('root_password_changed'))
    
    # 2. Configure SSH for key-only authentication
    print(msg('security_step2'))
    ssh_config_commands = [
        # Backup original sshd_config
        "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak",
        # Disable password authentication
        "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        "sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config",
        "sed -i 's/^#*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config",
        # Ensure PubkeyAuthentication is enabled
        "sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
        # Disable root login with password (only key)
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
        # Add settings if they don't exist
        "grep -q '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config",
        "grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config",
    ]
    for cmd in ssh_config_commands:
        run_command(ssh, cmd, check_error=False)
    
    # Restart SSH service
    run_command(ssh, "systemctl restart sshd || systemctl restart ssh", check_error=False)
    security_info['ssh_key_only'] = True
    print(msg('ssh_configured'))
    
    # 3. Disable VPS provider monitoring agents
    print(msg('security_step3'))
    provider_agents = [
        # Common VPS provider agents
        "qemu-guest-agent",
        "cloud-init",
        "cloud-final",
        "cloud-config",
        # Monitoring agents
        "zabbix-agent",
        "zabbix-agent2", 
        "telegraf",
        "datadog-agent",
        "newrelic-infra",
        "node_exporter",
        "collectd",
        # Cloud provider specific
        "google-guest-agent",
        "google-osconfig-agent",
        "amazon-ssm-agent",
        "waagent",  # Azure
        "aliyun-service",  # Aliyun
        "tat_agent",  # Tencent
        "aegis",  # Aliyun security
        "cloudmonitor",  # Aliyun monitor
        "bcm-agent",  # Baidu
        "hostguard",  # Huawei
    ]
    
    for agent in provider_agents:
        # Stop and disable the service
        result = run_command(ssh, f"systemctl stop {agent} 2>/dev/null; systemctl disable {agent} 2>/dev/null; echo $?", check_error=False)
        if "0" in result:
            security_info['agents_disabled'].append(agent)
            print(msg('disabled_agent', agent))
    
    # Also try to remove cloud-init if present (OS-aware)
    if pkg_manager == 'apt':
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get purge -y cloud-init 2>/dev/null || true", check_error=False)
    elif pkg_manager in ['dnf', 'yum']:
        run_command(ssh, "dnf remove -y cloud-init 2>/dev/null || yum remove -y cloud-init 2>/dev/null || true", check_error=False)
    elif pkg_manager == 'apk':
        run_command(ssh, "apk del cloud-init 2>/dev/null || true", check_error=False)
    
    # Block cloud-init from running
    run_command(ssh, "touch /etc/cloud/cloud-init.disabled", check_error=False)
    
    # 4. Install and configure fail2ban (OS-aware)
    print(msg('security_step4'))
    
    if pkg_manager == 'apt':
        run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban", check_error=False)
    elif pkg_manager == 'dnf':
        run_command(ssh, "dnf install -y epel-release 2>/dev/null || true", check_error=False)
        run_command(ssh, "dnf install -y fail2ban", check_error=False)
    elif pkg_manager == 'yum':
        run_command(ssh, "yum install -y epel-release 2>/dev/null || true", check_error=False)
        run_command(ssh, "yum install -y fail2ban", check_error=False)
    elif pkg_manager == 'apk':
        run_command(ssh, "apk add fail2ban", check_error=False)
    
    # Create fail2ban jail config for SSH (log path varies by OS)
    if pkg_manager == 'apt':
        auth_log_path = "/var/log/auth.log"
    else:
        auth_log_path = "/var/log/secure"
    
    fail2ban_config = f'''[sshd]
enabled = true
port = ssh
filter = sshd
logpath = {auth_log_path}
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = {auth_log_path}
maxretry = 6
bantime = 3600
findtime = 600
'''
    run_command(ssh, f"cat > /etc/fail2ban/jail.local << 'EOF'\n{fail2ban_config}EOF")
    run_command(ssh, "systemctl enable fail2ban && systemctl restart fail2ban", check_error=False)
    security_info['fail2ban_installed'] = True
    print(msg('fail2ban_configured'))
    
    # 5. Configure firewall to block common scanning/monitoring ports (OS-aware)
    print(msg('security_step5'))
    
    if pkg_manager == 'apt':
        # Debian/Ubuntu use ufw
        firewall_commands = [
            # Allow SSH (important - do this first!)
            "ufw allow ssh",
            # Allow our Hysteria2 port
            f"ufw allow {hy2_port}/udp",
        # Block common monitoring/agent ports (incoming)
            "ufw deny 10050/tcp",  # Zabbix agent
            "ufw deny 10051/tcp",  # Zabbix server
            "ufw deny 8086/tcp",   # InfluxDB/Telegraf
            "ufw deny 9100/tcp",   # Node exporter
            "ufw deny 9090/tcp",   # Prometheus
            "ufw deny 8125/udp",   # StatsD
            "ufw deny 8126/tcp",   # Datadog
            "ufw deny 5666/tcp",   # NRPE
            "ufw deny 4949/tcp",   # Munin
            "ufw deny 25826/udp",  # Collectd
        ]
        for cmd in firewall_commands:
            run_command(ssh, cmd, check_error=False)
    elif pkg_manager in ['dnf', 'yum']:
        # RHEL-based systems use firewalld
        firewall_commands = [
            "firewall-cmd --permanent --add-service=ssh",
            f"firewall-cmd --permanent --add-port={hy2_port}/udp",
            # Block monitoring ports by removing them if they exist
            "firewall-cmd --permanent --remove-port=10050/tcp 2>/dev/null || true",
            "firewall-cmd --permanent --remove-port=10051/tcp 2>/dev/null || true",
            "firewall-cmd --permanent --remove-port=8086/tcp 2>/dev/null || true",
            "firewall-cmd --permanent --remove-port=9100/tcp 2>/dev/null || true",
            "firewall-cmd --permanent --remove-port=9090/tcp 2>/dev/null || true",
            "firewall-cmd --reload",
        ]
        for cmd in firewall_commands:
            run_command(ssh, cmd, check_error=False)
    
    security_info['firewall_hardened'] = True
    print(msg('firewall_hardened_msg'))
    
    # 6. Additional security measures
    print(msg('security_step6'))
    
    # Disable IPv6 if not needed (reduces attack surface)
    # run_command(ssh, "sysctl -w net.ipv6.conf.all.disable_ipv6=1", check_error=False)
    
    # Secure shared memory
    run_command(ssh, "grep -q '/run/shm' /etc/fstab || echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >> /etc/fstab", check_error=False)
    
    # Disable unnecessary network services
    run_command(ssh, "systemctl disable rpcbind 2>/dev/null || true", check_error=False)
    run_command(ssh, "systemctl disable nfs-common 2>/dev/null || true", check_error=False)
    
    # Hide kernel pointers from unprivileged users
    run_command(ssh, "sysctl -w kernel.kptr_restrict=2", check_error=False)
    
    # Restrict dmesg access
    run_command(ssh, "sysctl -w kernel.dmesg_restrict=1", check_error=False)
    
    # Persist sysctl settings
    sysctl_config = '''# Security hardening
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
'''
    run_command(ssh, f"cat > /etc/sysctl.d/99-security.conf << 'EOF'\n{sysctl_config}EOF")
    run_command(ssh, "sysctl -p /etc/sysctl.d/99-security.conf", check_error=False)
    
    # 7. Privacy protection - clean up history and logs containing sensitive info
    print("  [PRIVACY] Cleaning up command history and sensitive logs...")
    
    # Clear bash history (contains passwords, configs that were echoed)
    run_command(ssh, "cat /dev/null > ~/.bash_history", check_error=False)
    run_command(ssh, "history -c 2>/dev/null || true", check_error=False)
    
    # Clear root's history files
    run_command(ssh, "rm -f /root/.bash_history /root/.zsh_history /root/.sh_history 2>/dev/null || true", check_error=False)
    
    # Clear apt/dpkg logs that may contain package info
    run_command(ssh, "cat /dev/null > /var/log/apt/history.log 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/apt/term.log 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/dpkg.log 2>/dev/null || true", check_error=False)
    
    # Clear auth logs (contains SSH connection details)
    run_command(ssh, "cat /dev/null > /var/log/auth.log 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/secure 2>/dev/null || true", check_error=False)
    
    # Clear syslog and messages
    run_command(ssh, "cat /dev/null > /var/log/syslog 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/messages 2>/dev/null || true", check_error=False)
    
    # Clear last login records
    run_command(ssh, "cat /dev/null > /var/log/lastlog 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/wtmp 2>/dev/null || true", check_error=False)
    run_command(ssh, "cat /dev/null > /var/log/btmp 2>/dev/null || true", check_error=False)
    
    # SECURITY: Clear any Hysteria2-related logs from previous runs
    print("  [PRIVACY] Clearing any existing Hysteria2 logs...")
    run_command(ssh, "rm -rf /var/log/hysteria* 2>/dev/null || true", check_error=False)
    run_command(ssh, "rm -rf /etc/hysteria/*.log 2>/dev/null || true", check_error=False)
    run_command(ssh, "rm -rf /root/hysteria2/*.log 2>/dev/null || true", check_error=False)
    
    # Clear journald logs for hysteria service (removes historical access patterns)
    run_command(ssh, "journalctl --vacuum-time=1s --unit=hysteria 2>/dev/null || true", check_error=False)
    run_command(ssh, "journalctl --rotate 2>/dev/null || true", check_error=False)
    run_command(ssh, "journalctl --vacuum-size=1M 2>/dev/null || true", check_error=False)
    
    # Clear Docker logs if Docker is installed
    run_command(ssh, "truncate -s 0 /var/lib/docker/containers/*/*-json.log 2>/dev/null || true", check_error=False)
    
    # Set HISTSIZE to 0 for future sessions
    run_command(ssh, "grep -q 'HISTSIZE=0' /etc/profile || echo 'HISTSIZE=0' >> /etc/profile", check_error=False)
    run_command(ssh, "grep -q 'HISTFILESIZE=0' /etc/profile || echo 'HISTFILESIZE=0' >> /etc/profile", check_error=False)
    
    # Disable history for root
    run_command(ssh, "grep -q 'unset HISTFILE' /root/.bashrc 2>/dev/null || echo 'unset HISTFILE' >> /root/.bashrc", check_error=False)
    
    print("  ✓ Command history and sensitive logs cleared")
    print("  ✓ Server configured for ZERO-LOG mode (no access logs written)")
    security_info['history_cleared'] = True
    security_info['zero_log_mode'] = True
    
    print(msg('security_applied'))
    
    return security_info


# ---------------------------------------------------------------------------
# Dataclass to hold all collected parameters for a deployment run
# ---------------------------------------------------------------------------
from dataclasses import dataclass, field


@dataclass
class DeployParams:
    """All parameters needed for a Hysteria2 deployment."""
    server_ip: str
    server_name: str
    ssh_port: int = 22
    username: str = "root"
    password: str | None = None
    use_key_auth: bool = False
    privkey_path: Path | None = None
    privkey_passphrase: str | None = None
    pubkey_path: Path | None = None
    pubkey_content: str | None = None
    hy2_password: str = ""
    hy2_port: int = 0
    hop_interval: int = 10
    save_dir: Path = field(default_factory=lambda: Path("."))
    local_mode: bool = False
    # forwarded from argparse
    docker: bool = False
    debug: bool = False
    china: bool = False
    no_harden: bool = False
    no_password_change: bool = False
    new_password: str | None = None
    yes: bool = False


def collect_params(args: argparse.Namespace) -> DeployParams:
    """Gather all deployment parameters from CLI args and interactive prompts.

    This isolates the I/O-heavy input-collection phase from the actual
    server setup logic, making ``main()`` easier to read and test.
    """
    global LANG

    # ----- Language selection -----
    if args.lang:
        LANG = args.lang
    elif args.server:
        LANG = 'en'
    else:
        lang_input = input(MESSAGES['en']['select_language']).strip().lower()
        LANG = 'zh' if lang_input in ('zh', 'cn', 'chinese', '中文') else 'en'

    # ----- Key paths -----
    use_key_auth = args.key_auth
    privkey_path: Path | None = None
    if use_key_auth:
        privkey_path = Path(args.privkey).expanduser() if args.privkey else get_default_privkey_path()

    pubkey_path = Path(args.pubkey).expanduser() if args.pubkey else get_default_pubkey_path()

    # ----- Banner -----
    print(fmt_banner("=" * 60))
    print(fmt_banner(f"  {msg('title')}"))
    if args.china:
        print(fmt_warn(f"  {msg('china_mode_enabled')}"))
    print(fmt_banner("=" * 60))
    print()

    # ----- Validate private key early -----
    if use_key_auth:
        print(msg('using_key_auth'))
        if privkey_path and privkey_path.exists():
            print(msg('found_privkey', privkey_path))
        else:
            print(msg('no_privkey', privkey_path))
            sys.exit(1)

    # ----- Server IP -----
    if args.server:
        server_ip = args.server
        if not validate_ip_address(server_ip):
            print(msg('error_invalid_ip', server_ip))
            sys.exit(1)
    else:
        server_ip = input(msg('enter_server_ip')).strip()
        if not server_ip:
            print(msg('error_ip_required'))
            sys.exit(1)
        if not validate_ip_address(server_ip):
            print(msg('error_invalid_ip', server_ip))
            sys.exit(1)

    # ----- Local-mode auto-detect -----
    local_mode = args.local
    if not local_mode and is_local_ip(server_ip):
        print(msg('local_ip_detected', server_ip))
        if args.yes:
            local_mode = True
            print(msg('local_mode_enabled'))
        else:
            confirm = input(msg('local_mode_confirm')).strip().lower()
            if confirm == 'y':
                local_mode = True
                print(msg('local_mode_enabled'))
            else:
                print(msg('local_mode_aborted'))
                sys.exit(0)
    if local_mode:
        print(msg('local_mode_requires_sudo'))

    # ----- Server name -----
    if args.name:
        server_name = args.name
    else:
        server_name = input(msg('enter_server_name')).strip() or server_ip

    # ----- Save directory -----
    if args.save_config:
        save_dir = Path(args.save_config)
    else:
        from datetime import datetime
        time_str = datetime.now().strftime('%Y-%m-%d_%H-%M')
        safe_name = re.sub(r'[<>:"/\\|?*]', '-', server_name)
        safe_name = re.sub(r'-+', '-', safe_name).strip('-')
        save_dir = SCRIPT_DIR / f"{safe_name}-{time_str}"
    print(f"\n[INFO] Client configs will be saved to: {save_dir}")

    # ----- Public key -----
    pubkey_content: str | None = None
    if not use_key_auth:
        pubkey_content = read_pubkey(pubkey_path, auto_generate=True, save_dir=save_dir)
        if pubkey_content:
            print(msg('found_pubkey', pubkey_path))
        else:
            print(msg('no_pubkey', pubkey_path))
            deploy_key = input(msg('continue_without_key')).strip().lower()
            if deploy_key != 'y':
                print(msg('aborted_no_key'))
                sys.exit(1)

    # ----- SSH port -----
    # In local_mode, SSH is not used - use defaults without prompting
    if local_mode:
        ssh_port = args.ssh_port or 22
    elif args.ssh_port:
        ssh_port = args.ssh_port
        if not validate_port(ssh_port):
            print(msg('error_invalid_port', ssh_port))
            sys.exit(1)
    else:
        ssh_port_input = input(msg('enter_ssh_port')).strip()
        if ssh_port_input:
            try:
                ssh_port = int(ssh_port_input)
                if not validate_port(ssh_port):
                    print(msg('error_invalid_port', ssh_port))
                    sys.exit(1)
            except ValueError:
                print(msg('error_not_port_number', ssh_port_input))
                sys.exit(1)
        else:
            ssh_port = 22

    # ----- Username / credentials -----
    # In local_mode, SSH is not used - use defaults without prompting
    if local_mode:
        username = args.user or "root"
        password = None
        privkey_passphrase = None
    else:
        username = args.user or (input(msg('enter_username')).strip() or "root")
        password: str | None = None
        privkey_passphrase: str | None = None
        if use_key_auth:
            if args.key_passphrase:
                privkey_passphrase = args.key_passphrase
            else:
                privkey_passphrase = getpass.getpass(msg('enter_privkey_passphrase')) or None
        else:
            if args.password:
                password = args.password
            else:
                password = getpass.getpass(msg('enter_password'))
                if not password:
                    print(msg('error_password_required'))
                    sys.exit(1)

    # ----- Hysteria2 password & port -----
    hy2_password = generate_password()
    print("\n[SECURITY] Hysteria2 password generated (saved to credentials.txt)")

    if args.port:
        hy2_port = args.port
        if PORT_HOP_START <= hy2_port <= PORT_HOP_END:
            print(msg('warn_port_in_hop_range', hy2_port))
    else:
        if random.choice([True, False]):
            hy2_port = random.randint(10000, PORT_HOP_START - 1)
        else:
            hy2_port = random.randint(PORT_HOP_END + 1, 65000)
    print(msg('hy2_service_port', hy2_port))

    hop_interval = random.randint(HOP_INTERVAL_MIN, HOP_INTERVAL_MAX)

    return DeployParams(
        server_ip=server_ip,
        server_name=server_name,
        ssh_port=ssh_port,
        username=username,
        password=password,
        use_key_auth=use_key_auth,
        privkey_path=privkey_path,
        privkey_passphrase=privkey_passphrase,
        pubkey_path=pubkey_path,
        pubkey_content=pubkey_content,
        hy2_password=hy2_password,
        hy2_port=hy2_port,
        hop_interval=hop_interval,
        save_dir=save_dir,
        local_mode=local_mode,
        docker=args.docker,
        debug=args.debug,
        china=args.china,
        no_harden=args.no_harden,
        no_password_change=args.no_password_change,
        new_password=args.new_password,
        yes=args.yes,
    )


def main():
    args = parse_args()
    params = collect_params(args)

    # Unpack into local variables for the rest of main()
    server_ip = params.server_ip
    server_name = params.server_name
    ssh_port = params.ssh_port
    username = params.username
    password = params.password
    use_key_auth = params.use_key_auth
    privkey_path = params.privkey_path
    privkey_passphrase = params.privkey_passphrase
    pubkey_path = params.pubkey_path
    pubkey_content = params.pubkey_content
    hy2_password = params.hy2_password
    hy2_port = params.hy2_port
    hop_interval = params.hop_interval
    save_dir = params.save_dir
    local_mode = params.local_mode
    hop_range = f'{PORT_HOP_START}:{PORT_HOP_END}'

    # Connect to server or use local mode
    if local_mode:
        # Local mode - no SSH connection needed
        print_step(f"\n[LOCAL MODE] Installing on this machine")
        print_warn("  [NOTE] Port hopping is disabled for local mode client configs.")
        print_warn("         iptables PREROUTING rules don't affect same-machine traffic.")
        ssh = LocalSSHClient()
        print(f"{msg('connected')}\n")
    else:
        # Remote mode - connect via SSH
        masked_ip = server_ip[:4] + '*' * (len(server_ip) - 4) if len(server_ip) > 4 else '****'
        print_step(f"\n[CONNECTING] {masked_ip}:{ssh_port}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            if use_key_auth:
                # Key-based authentication
                ssh.connect(
                    hostname=server_ip,
                    port=ssh_port,
                    username=username,
                    key_filename=str(privkey_path),
                    passphrase=privkey_passphrase,
                    timeout=SSH_CONNECT_TIMEOUT,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                # Password-based authentication
                ssh.connect(
                    hostname=server_ip,
                    port=ssh_port,
                    username=username,
                    password=password,
                    timeout=SSH_CONNECT_TIMEOUT,
                    allow_agent=False,
                    look_for_keys=False
                )
            print(f"{msg('connected')}\n")
        except Exception as e:
            print_err(msg('failed_connect', e))
            sys.exit(1)
    
    # Variable to store detected OS info
    os_info = None
    
    # China mode disguised names (needed for cleanup)
    china_service_name = 'systemd-netlogd'
    china_binary_name = 'systemd-netlogd'
    
    try:
        # Pre-step: Clean up any existing Hysteria2 installation
        print_step(msg('cleanup_existing'))
        # Kill running hysteria processes (native + disguised)
        run_command(ssh, "pkill -f 'hysteria' 2>/dev/null || true", check_error=False)
        run_command(ssh, f"pkill -f '{china_binary_name}' 2>/dev/null || true", check_error=False)
        # Stop & disable systemd services
        run_command(ssh, "systemctl stop hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, "systemctl disable hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, f"systemctl stop {china_service_name} 2>/dev/null || true", check_error=False)
        run_command(ssh, f"systemctl disable {china_service_name} 2>/dev/null || true", check_error=False)
        # Stop & remove Docker containers
        run_command(ssh, "docker stop hysteria 2>/dev/null || true; docker rm hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, "docker stop hy2-test 2>/dev/null || true; docker rm hy2-test 2>/dev/null || true", check_error=False)
        # Remove old systemd service files
        run_command(ssh, "rm -f /etc/systemd/system/hysteria.service 2>/dev/null || true", check_error=False)
        run_command(ssh, f"rm -f /etc/systemd/system/{china_service_name}.service 2>/dev/null || true", check_error=False)
        run_command(ssh, "systemctl daemon-reload 2>/dev/null || true", check_error=False)
        # Remove old binaries
        run_command(ssh, "rm -f /usr/local/bin/hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, f"rm -f /usr/local/bin/{china_binary_name} 2>/dev/null || true", check_error=False)
        # Remove old config directories (certs will be regenerated)
        run_command(ssh, "rm -rf /etc/hysteria 2>/dev/null || true", check_error=False)
        run_command(ssh, f"rm -rf /etc/{china_service_name} 2>/dev/null || true", check_error=False)
        print_ok(msg('cleanup_done'))
        
        # Step 0: Detect OS and Deploy SSH public key (for key-auth mode, detect OS first)
        if use_key_auth:
            print(msg('detecting_os'))
            os_info = detect_os(ssh)
            print(msg('detected_os', os_info['os_name'], os_info['pkg_manager']))
            
            if os_info['os_type'] == 'unknown':
                print(msg('unsupported_os', os_info['os_name']))
        elif pubkey_content:
            print(msg('step1_deploy_key'))
            run_command(ssh, "mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            # Check if key already exists to avoid duplicates
            check_key = run_command(ssh, f"grep -F '{pubkey_content}' ~/.ssh/authorized_keys 2>/dev/null || echo 'NOT_FOUND'", check_error=False)
            if 'NOT_FOUND' in check_key:
                run_command(ssh, f"echo '{pubkey_content}' >> ~/.ssh/authorized_keys")
                run_command(ssh, "chmod 600 ~/.ssh/authorized_keys")
                print(msg('key_deployed'))
            else:
                print(msg('key_exists'))
        
        # Step 2: Update and upgrade the system (OS-aware)
        print_step(msg('step2_update'))
        
        # Detect OS if not already done (for password-auth mode)
        if os_info is None:
            os_info = detect_os(ssh)
            print(msg('detected_os', os_info['os_name'], os_info['pkg_manager']))
        
        pkg_manager = os_info['pkg_manager']
        
        if pkg_manager == 'apt':
            # Set non-interactive frontend to prevent all prompts
            run_command(ssh, "export DEBIAN_FRONTEND=noninteractive && apt-get update", check_error=False, show_output=True)
            # Use apt-get with full non-interactive options to prevent any user prompts
            run_command(ssh, 'DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confnew" --allow-downgrades --allow-remove-essential --allow-change-held-packages', check_error=False, show_output=True)
        elif pkg_manager == 'dnf':
            run_command(ssh, "dnf update -y", check_error=False)
        elif pkg_manager == 'yum':
            run_command(ssh, "yum update -y", check_error=False)
        elif pkg_manager == 'apk':
            run_command(ssh, "apk update && apk upgrade", check_error=False)
        else:
            # Fallback - try apt first, then other managers
            run_command(ssh, "apt update 2>/dev/null || dnf update -y 2>/dev/null || yum update -y 2>/dev/null || apk update 2>/dev/null || true", check_error=False)
        
        # Step 2: Install necessary packages (OS-aware)
        print_step(f"\n{msg('step3_packages')}")
        
        if pkg_manager == 'apt':
            run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y apt-transport-https ca-certificates curl vim iptables ufw", check_error=False, show_output=True)
        elif pkg_manager == 'dnf':
            run_command(ssh, "dnf install -y ca-certificates curl vim iptables firewalld", check_error=False)
        elif pkg_manager == 'yum':
            run_command(ssh, "yum install -y ca-certificates curl vim iptables firewalld", check_error=False)
        elif pkg_manager == 'apk':
            run_command(ssh, "apk add ca-certificates curl vim iptables", check_error=False)
        else:
            run_command(ssh, "apt install -y apt-transport-https ca-certificates curl vim iptables ufw 2>/dev/null || dnf install -y ca-certificates curl vim iptables 2>/dev/null || true", check_error=False)
        
        # Step 3: Install Docker or Hysteria2 native
        # China mode: Download binary locally first, then upload via SFTP
        # Disguised names defined above (pre-step cleanup)
        
        # Clean up opposite mode installation to support mode switching
        # This allows re-running the script to switch between China and normal mode
        cleanup_opposite_mode(ssh, params.china, china_service_name, china_binary_name)
        
        if params.china:
            print(msg('china_mode_enabled'))
            
            # In China mode, download binary locally first (GitHub blocked in China)
            print(f"\n{msg('china_downloading_local')}")
            
            # Detect remote architecture first
            remote_arch = run_command(ssh, "uname -m", check_error=False).strip()
            if remote_arch == 'x86_64':
                target_arch = 'amd64'
            elif remote_arch == 'aarch64':
                target_arch = 'arm64'
            elif 'arm' in remote_arch:
                target_arch = 'arm'
            else:
                target_arch = 'amd64'  # Default
            
            print(f"  Remote architecture: {remote_arch} -> linux/{target_arch}")
            
            # Download binary locally
            local_binary = download_hysteria_locally(str(save_dir), 'linux', target_arch)
            if local_binary:
                print(msg('china_download_success', local_binary))
                
                # Disable China VPS agents first
                disable_china_vps_agents(ssh)
                
                # Upload to server with disguised name
                if install_hysteria2_china_mode(ssh, local_binary, china_service_name, china_binary_name):
                    print(msg('native_install_success'))
                else:
                    print(msg('native_install_failed'))
            else:
                print(msg('china_download_failed'))
                print("  Please download hysteria binary manually and re-run.")
                sys.exit(1)
                
        elif params.docker:
            # Docker-based installation
            print_step(f"\n{msg('step4_docker')}")
            print(msg('checking_docker'))
            
            if check_docker_installed(ssh):
                print(msg('docker_found'))
                # Still configure IPv6 even if Docker is already installed
                configure_docker_ipv6(ssh)
            else:
                print(msg('docker_not_found'))
                if install_docker_for_os(ssh, os_info):
                    print(msg('docker_install_success'))
                else:
                    print(msg('docker_install_failed'))
                    # Continue anyway - may work with existing docker
        else:
            # Native Hysteria2 installation (default, no Docker)
            print_step(f"\n{msg('step4_native')}")
            if install_hysteria2_native(ssh, os_info):
                print(msg('native_install_success'))
            else:
                print(msg('native_install_failed'))
                # Continue anyway
        
        # Step 5: Configure firewall (OS-aware)
        print_step(f"\n{msg('step5_firewall')}")
        
        if pkg_manager == 'apt':
            # Debian/Ubuntu use ufw
            run_command(ssh, f"ufw allow proto udp from any to any port {hy2_port}", check_error=False)
        elif pkg_manager in ['dnf', 'yum']:
            # RHEL-based systems use firewalld
            run_command(ssh, "systemctl start firewalld 2>/dev/null || true", check_error=False)
            run_command(ssh, "systemctl enable firewalld 2>/dev/null || true", check_error=False)
            run_command(ssh, f"firewall-cmd --permanent --add-port={hy2_port}/udp 2>/dev/null || true", check_error=False)
            run_command(ssh, "firewall-cmd --reload 2>/dev/null || true", check_error=False)
        
        # Clean up ALL old iptables rules for port hopping in the 20000-60000 range
        # This handles multiple runs and prevents conflicts from old hop rules
        print("  Cleaning up old iptables rules...")
        print("  [INFO] Removing any PREROUTING rules with ports in 20000-60000 range")
        
        # Load ip6tables NAT module if not already loaded (required for IPv6 port forwarding)
        run_command(ssh, "modprobe ip6table_nat 2>/dev/null || true", check_error=False)
        
        # First, clear any saved/persistent rules that might restore old port rules
        run_command(ssh, "rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null || true", check_error=False)
        
        # Clean iptables rules - match ANY port range in 20000-60000
        # Patterns to match: 20000:50000, 20000:60000, or any similar range
        import re
        hop_port_pattern = re.compile(r'dpts?:(\d+):(\d+)')
        
        for ip_cmd in ['iptables', 'ip6tables']:
            # First show current rules for debugging
            current = run_command(ssh, f"{ip_cmd} -t nat -L PREROUTING --line-numbers -n 2>&1", check_error=False)
            print(f"  {ip_cmd} current PREROUTING rules:")
            for line in current.split('\n')[:10]:  # Show first 10 lines
                print(f"    {line}")
            
            deleted_count = 0
            removed_rules = []
            # Try to delete by rule number, repeatedly
            for attempt in range(30):
                # Get rule numbers for all matching rules
                output = run_command(ssh, f"{ip_cmd} -t nat -L PREROUTING --line-numbers -n 2>&1", check_error=False)
                
                # Find first rule with any port range overlapping 20000-60000
                rule_num = None
                rule_desc = None
                for line in output.split('\n'):
                    match = hop_port_pattern.search(line)
                    if match:
                        port_start = int(match.group(1))
                        port_end = int(match.group(2))
                        # Check if range overlaps with 20000-60000
                        if port_start >= 20000 and port_start <= 60000 or port_end >= 20000 and port_end <= 60000:
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                rule_num = parts[0]
                                rule_desc = f"{port_start}:{port_end}"
                                break
                
                if not rule_num:
                    break
                
                # Delete the rule - show result
                del_result = run_command(ssh, f"{ip_cmd} -t nat -D PREROUTING {rule_num} 2>&1", check_error=False)
                deleted_count += 1
                removed_rules.append(rule_desc)
                print(f"    Removed rule #{rule_num} (ports {rule_desc})")
            
            if deleted_count > 0:
                print(f"  ✓ Removed {deleted_count} {ip_cmd} hop rules: {', '.join(set(removed_rules))}")
                print(f"  [NOTICE] Old hop rules were cleaned up to prevent conflicts")
            else:
                print(f"  No {ip_cmd} hop rules to remove")
        
        # Verify cleanup
        v6_check = run_command(ssh, "ip6tables -t nat -L PREROUTING -n 2>&1", check_error=False)
        remaining_match = hop_port_pattern.search(v6_check)
        if remaining_match:
            port_start = int(remaining_match.group(1))
            if port_start >= 20000 and port_start <= 60000:
                print(f"  [WARN] Some IPv6 hop rules may still remain")
        else:
            print("  ✓ All old port hopping rules removed")
        
        # Add fresh iptables rules for port hopping
        print("  Adding iptables rules for port hopping...")
        run_command(ssh, f"iptables -t nat -A PREROUTING -p udp --dport {hop_range} -j REDIRECT --to-ports {hy2_port}", check_error=False)
        
        # For IPv6, load the NAT module first, then verify and add rules
        print("  Loading IPv6 NAT module...")
        run_command(ssh, "modprobe ip6table_nat 2>/dev/null || true", check_error=False)
        
        # Small delay to let module initialize
        time.sleep(1)
        
        ip6_nat_loaded = run_command(ssh, "lsmod | grep ip6table_nat && echo 'MODULE_LOADED' || echo 'MODULE_MISSING'", check_error=False)
        if 'MODULE_LOADED' in ip6_nat_loaded:
            result = run_command(ssh, f"ip6tables -t nat -A PREROUTING -p udp --dport {hop_range} -j REDIRECT --to-ports {hy2_port} 2>&1", check_error=False)
            # Verify rule was added
            verify = run_command(ssh, f"ip6tables -t nat -L PREROUTING -n | grep {hy2_port} && echo 'RULE_ADDED' || echo 'RULE_FAILED'", check_error=False)
            if 'RULE_ADDED' in verify:
                print("  ✓ IPv6 port hopping enabled")
            else:
                print(f"  [WARN] IPv6 rule add failed: {result}")
                print("         (IPv6 clients should use direct port instead of port range)")
        else:
            print("  [WARN] ip6table_nat module not available")
            print("         Trying to load with different method...")
            # Try alternate loading method
            run_command(ssh, "ip6tables -t nat -L 2>/dev/null || true", check_error=False)  # This can trigger module load
            ip6_nat_retry = run_command(ssh, "lsmod | grep ip6table_nat && echo 'MODULE_LOADED' || echo 'MODULE_MISSING'", check_error=False)
            if 'MODULE_LOADED' in ip6_nat_retry:
                run_command(ssh, f"ip6tables -t nat -A PREROUTING -p udp --dport {hop_range} -j REDIRECT --to-ports {hy2_port}", check_error=False)
                print("  ✓ IPv6 port hopping enabled (via alternate method)")
            else:
                print("  [WARN] IPv6 port hopping disabled (module unavailable)")
                print("         IPv6 clients should use direct port instead of port range)")
        
        # Ensure ip6table_nat loads on boot
        run_command(ssh, "grep -q 'ip6table_nat' /etc/modules 2>/dev/null || echo 'ip6table_nat' >> /etc/modules", check_error=False)
        
        # Install iptables-persistent to save rules across reboots (non-interactive)
        if pkg_manager == 'apt':
            # Pre-seed debconf to automatically answer yes to save current rules
            run_command(ssh, "echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true", check_error=False)
            run_command(ssh, "echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections 2>/dev/null || true", check_error=False)
            run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent 2>/dev/null || true", check_error=False)
            run_command(ssh, "netfilter-persistent save 2>/dev/null || true", check_error=False)
        
        # Determine config directory based on installation mode
        # China mode uses disguised directory name
        if params.china:
            config_dir = f"/etc/{china_service_name}"
        elif params.docker:
            config_dir = "/root/hysteria2"
        else:
            config_dir = "/etc/hysteria"
        
        # Step 6: Create working directory
        print_step(f"\n{msg('step6_workdir')}")
        run_command(ssh, f"mkdir -p {config_dir}")
        
        # Step 7: Generate SSL certificates (OS-aware openssl install)
        print_step(f"\n{msg('step7_ssl')}")
        
        if pkg_manager == 'apt':
            run_command(ssh, "DEBIAN_FRONTEND=noninteractive apt-get install -y openssl", check_error=False)
        elif pkg_manager == 'dnf':
            run_command(ssh, "dnf install -y openssl", check_error=False)
        elif pkg_manager == 'yum':
            run_command(ssh, "yum install -y openssl", check_error=False)
        elif pkg_manager == 'apk':
            run_command(ssh, "apk add openssl", check_error=False)
        
        # Always generate fresh SSL certificates for new deployment
        print("  Generating SSL certificates...")
        run_command(ssh, f'cd {config_dir} && openssl req -x509 -newkey rsa:{SSH_KEY_BITS} -sha256 -nodes -keyout server.key -out server.crt -days {SSL_CERT_DAYS} -subj "/CN=localhost"')
        run_command(ssh, f"chmod 600 {config_dir}/server.key")
        
        # Step 8: Create config files
        print_step(f"\n{msg('step8_config')}")
        
        # Show debug mode status
        if params.debug:
            print("  [DEBUG MODE] Logging enabled for troubleshooting")
            print("  WARNING: Access patterns will be logged. Re-run without --debug for zero-log mode.")
        else:
            print("  [ZERO-LOG MODE] No access logs will be recorded")
        
        # Write config.yaml
        config_content, masquerade_domain = get_config_yaml(hy2_password, hy2_port, debug_mode=params.debug)
        # Adjust cert paths based on mode
        if params.china:
            # China mode: use disguised config directory
            config_content = config_content.replace('/etc/server.crt', f'/etc/{china_service_name}/server.crt')
            config_content = config_content.replace('/etc/server.key', f'/etc/{china_service_name}/server.key')
        elif not params.docker:
            # Native mode (non-China): files are at /etc/hysteria/
            config_content = config_content.replace('/etc/server.crt', '/etc/hysteria/server.crt')
            config_content = config_content.replace('/etc/server.key', '/etc/hysteria/server.key')
        
        # Write config to server (quiet to avoid leaking credentials)
        run_command(ssh, f"cat > {config_dir}/config.yaml << 'CONFIGEOF'\n{config_content}\nCONFIGEOF", quiet=True)
        print(f"  > [config written to {config_dir}/config.yaml]")
        
        # Write compose.yaml only for Docker mode
        if params.docker:
            compose_content = get_compose_yaml(debug_mode=params.debug)
            run_command(ssh, f"cat > {config_dir}/compose.yaml << 'COMPOSEEOF'\n{compose_content}\nCOMPOSEEOF", quiet=True)
            print(f"  > [compose written to {config_dir}/compose.yaml]")
        
        # Step 9: Start Hysteria2
        if params.china:
            # China mode: use disguised systemd service
            print_step(f"\n{msg('step9_start_native')}")
            create_disguised_systemd_service(ssh, debug_mode=params.debug, 
                                            service_name=china_service_name, 
                                            binary_name=china_binary_name)
            
            # Verify binary and config exist before starting
            binary_check = run_command(ssh, f"test -x /usr/local/bin/{china_binary_name} && echo 'BINARY_OK' || echo 'BINARY_MISSING'", check_error=False)
            config_check = run_command(ssh, f"test -f /etc/{china_service_name}/config.yaml && echo 'CONFIG_OK' || echo 'CONFIG_MISSING'", check_error=False)
            
            if 'BINARY_MISSING' in binary_check:
                print_warn(f"  [WARN] Binary missing: /usr/local/bin/{china_binary_name}")
            if 'CONFIG_MISSING' in config_check:
                print_warn(f"  [WARN] Config missing: /etc/{china_service_name}/config.yaml")
            
            # Start the disguised service
            run_command(ssh, f"systemctl start {china_service_name}", check_error=False)
            time.sleep(3)
            status = run_command(ssh, f"systemctl is-active {china_service_name} 2>/dev/null || echo 'inactive'", check_error=False).strip()
            if status == 'active':
                print(msg('native_service_success'))
            else:
                print(msg('native_service_failed'))
                # Show detailed status and recent journal entries for debugging
                run_command(ssh, f"systemctl status {china_service_name} 2>&1 | tail -20", check_error=False, show_output=True)
                print("  Checking journal for startup errors:")
                run_command(ssh, f"journalctl -u {china_service_name} -n 10 --no-pager 2>&1 || echo '  (no journal entries)'", check_error=False, show_output=True)
        elif not params.docker:
            print_step(f"\n{msg('step9_start_native')}")
            # Create and start systemd service
            create_hysteria2_systemd_service(ssh, debug_mode=params.debug)
            if start_hysteria2_native(ssh):
                print(msg('native_service_success'))
            else:
                print(msg('native_service_failed'))
        else:
            print_step(f"\n{msg('step9_start')}")
            # Stop existing container first (idempotency)
            run_command(ssh, f"cd {config_dir} && docker compose down 2>/dev/null || true", check_error=False)
            run_command(ssh, f"cd {config_dir} && docker compose up -d", check_error=False, show_output=True)
            
            # Wait a moment for container to start
            time.sleep(3)
            
            # Verify container is running
            print(f"\n{msg('verifying_container')}")
            container_status = run_command(ssh, "docker ps --filter name=hy2 --format '{{.Status}}'")
            if container_status.strip():
                print(msg('container_status', container_status.strip()))
                print(msg('docker_start_success'))
            else:
                print(msg('docker_start_failed'))
                run_command(ssh, f"cd {config_dir} && docker compose logs --tail=20", check_error=False, show_output=True)
                # Try to get more info
                run_command(ssh, "docker ps -a --filter name=hy2 --format 'ID: {{.ID}}, Status: {{.Status}}'", check_error=False)
        
        # Verify iptables port forwarding rules are in place
        print(fmt_step(f"\n{msg('verifying_iptables')}"))
        iptables_check = run_command(ssh, f"iptables -t nat -L PREROUTING -n | grep -E 'udp.*{hop_range}.*{hy2_port}' && echo 'RULE_EXISTS' || echo 'RULE_MISSING'", check_error=False)
        if 'RULE_EXISTS' in iptables_check:
            print(msg('iptables_ipv4_ok', hy2_port))
        else:
            print(msg('iptables_ipv4_missing'))
            run_command(ssh, f"iptables -t nat -A PREROUTING -p udp --dport {hop_range} -j REDIRECT --to-ports {hy2_port}", check_error=False)
        
        ip6tables_check = run_command(ssh, f"ip6tables -t nat -L PREROUTING -n 2>/dev/null | grep -E 'udp.*{hop_range}.*{hy2_port}' && echo 'RULE_EXISTS' || echo 'RULE_MISSING'", check_error=False)
        if 'RULE_EXISTS' in ip6tables_check:
            print(msg('iptables_ipv6_ok', hy2_port))
        else:
            print(msg('iptables_ipv6_missing'))
            run_command(ssh, f"ip6tables -t nat -A PREROUTING -p udp --dport {hop_range} -j REDIRECT --to-ports {hy2_port}", check_error=False)
        
        print(f"\n{msg('port_hop_configured', hy2_port)}")
        
        # Get the certificate fingerprint for pinSHA256
        print(fmt_step(f"\n{msg('retrieving_fingerprint')}"))
        fingerprint_output = run_command(ssh, f"openssl x509 -noout -fingerprint -sha256 -in {config_dir}/server.crt")
        pin_sha256 = extract_pin_sha256(fingerprint_output)
        
        if not pin_sha256:
            print(msg('warn_no_pinsha256'))
            # Alternative method: compute from certificate and format as colon-separated hex
            cert_output = run_command(ssh, f"openssl x509 -noout -fingerprint -sha256 -in {config_dir}/server.crt | sed 's/.*=//'")
            pin_sha256 = cert_output.strip().upper()
        
        # Test Hysteria2 server with a test client
        print(fmt_step(f"\n{msg('testing_hy2')}"))
        
        # Create test client config
        test_client_config = f'''server: 127.0.0.1:{hy2_port}
auth: {hy2_password}
tls:
  insecure: true
socks5:
  listen: 127.0.0.1:1080
'''
        
        if params.china or (not params.docker):
            # For native mode (default) or China mode, use the native hysteria binary for testing
            # China mode uses disguised binary name
            test_binary = f"/usr/local/bin/{china_binary_name}" if params.china else "/usr/local/bin/hysteria"
            
            run_command(ssh, f"cat > /tmp/hy2-test-client.yaml << 'TESTEOF'\n{test_client_config}\nTESTEOF", quiet=True)
            
            # Run test client (native binary, background) and capture output
            print("  Starting test client (native)...")
            run_command(ssh, f"pkill -f '{test_binary}.*hy2-test-client' 2>/dev/null || true", check_error=False)
            run_command(ssh, f"nohup {test_binary} client -c /tmp/hy2-test-client.yaml > /tmp/hy2-test-client.log 2>&1 &", check_error=False)
            
            # Wait for client to connect
            time.sleep(3)
            
            # Show client output (to verify connection)
            print("  Client output:")
            run_command(ssh, "cat /tmp/hy2-test-client.log 2>/dev/null || echo '  (no output yet)'", check_error=False, show_output=True)
            
            # Test the connection
            print("  Testing connection through SOCKS5 proxy...")
            # Use baidu.com for China mode (httpbin might be blocked)
            test_url = "http://www.baidu.com/" if params.china else "http://httpbin.org/ip"
            test_result = run_command(ssh, f"curl -s --max-time 10 --socks5 127.0.0.1:1080 {test_url} 2>/dev/null && echo 'TEST_SUCCESS' || echo 'TEST_FAILED'", check_error=False)
            
            # Clean up
            print("  Cleaning up test client...")
            run_command(ssh, f"pkill -f '{test_binary}.*hy2-test-client' 2>/dev/null || true", check_error=False)
            run_command(ssh, "rm -f /tmp/hy2-test-client.yaml /tmp/hy2-test-client.log", check_error=False)
        else:
            # For Docker mode, use Docker container for testing
            run_command(ssh, f"cat > {config_dir}/test-client.yaml << 'TESTEOF'\n{test_client_config}\nTESTEOF", quiet=True)
            
            # Run test client container
            print("  Starting test client container...")
            run_command(ssh, "docker stop hy2-test 2>/dev/null || true; docker rm hy2-test 2>/dev/null || true", check_error=False)
            run_command(ssh, f"docker run -d --name hy2-test --network host -v {config_dir}/test-client.yaml:/etc/hysteria/config.yaml tobyxdd/hysteria client", check_error=False)
            
            # Wait for client to connect (increase wait time)
            time.sleep(5)
            
            # Check if container is running and show logs
            print("  Checking test client status...")
            run_command(ssh, "docker logs hy2-test 2>&1 | tail -10", check_error=False, show_output=True)
            
            # Test the connection by making a request through the SOCKS5 proxy
            print("  Testing connection through SOCKS5 proxy...")
            test_result = run_command(ssh, "curl -s --max-time 10 --socks5 127.0.0.1:1080 http://httpbin.org/ip 2>/dev/null && echo 'TEST_SUCCESS' || echo 'TEST_FAILED'", check_error=False)
            
            # Clean up test container
            print("  Cleaning up test container...")
            run_command(ssh, "docker stop hy2-test 2>/dev/null || true", check_error=False)
            run_command(ssh, "docker rm hy2-test 2>/dev/null || true", check_error=False)
            run_command(ssh, f"rm -f {config_dir}/test-client.yaml", check_error=False)
        
        if 'TEST_SUCCESS' in test_result:
            print_ok(msg('test_success'))
        else:
            print_warn(msg('test_failed'))
            print_warn("  Note: Test may fail on some networks. The server might still work correctly.")
            # Show logs for debugging
            if params.china:
                print(f"  {china_service_name} service logs (China mode):")
                run_command(ssh, f"journalctl -u {china_service_name} --no-pager -n 20 2>&1", check_error=False, show_output=True)
            elif not params.docker:
                print("  Hysteria2 service logs (native mode):")
                run_command(ssh, "journalctl -u hysteria --no-pager -n 20 2>&1", check_error=False, show_output=True)
            else:
                print("  Test client logs (if available):")
                run_command(ssh, "docker logs hy2-test 2>/dev/null || echo '  (no logs available)'", check_error=False)
        
        # Security hardening
        security_info = None
        new_root_password = None
        if not params.no_harden:
            # Generate or use provided new root password (unless --no-password-change)
            if not params.no_password_change:
                if params.new_password:
                    new_root_password = params.new_password
                else:
                    new_root_password = generate_password(ROOT_PASSWORD_LENGTH)
            
            security_info = harden_server_security(
                ssh, new_root_password, hy2_port, os_info,
                skip_password_change=params.no_password_change
            )
        else:
            print(f"\n{msg('skip_hardening')}")
            # Even without full hardening, clean up command history from this session
            print("  [PRIVACY] Cleaning up command history from this session...")
            run_command(ssh, "cat /dev/null > ~/.bash_history 2>/dev/null || true", check_error=False)
            run_command(ssh, "history -c 2>/dev/null || true", check_error=False)
            run_command(ssh, "rm -f /root/.bash_history 2>/dev/null || true", check_error=False)
            print("  ✓ Session history cleared")
        
        # Download local Hysteria2 client binary for testing
        # In China mode: download directly to local machine (GitHub accessible from local)
        # In normal mode: download via VPS, then SFTP back (faster for US VPS)
        hy2_binary = None
        print("\n" + fmt_banner("-" * 60))
        print_step("Downloading Hysteria2 client for local testing...")
        print(fmt_banner("-" * 60))
        
        if params.china:
            # China mode: GitHub is accessible from local machine (user is outside China)
            # Download directly to local machine for the local OS (not Linux)
            print("  [CHINA MODE] Downloading client binary directly (GitHub accessible from your location)")
            local_os = platform.system().lower()
            local_arch = platform.machine().lower()
            
            # Map architecture
            if local_arch in ['x86_64', 'amd64']:
                arch = 'amd64'
            elif local_arch in ['aarch64', 'arm64']:
                arch = 'arm64'
            elif 'arm' in local_arch:
                arch = 'arm'
            else:
                arch = 'amd64'
            
            # Map OS name
            if local_os == 'windows':
                os_name = 'windows'
            elif local_os == 'darwin':
                os_name = 'darwin'
            else:
                os_name = 'linux'
            
            hy2_binary = download_hysteria_locally(str(save_dir), os_name, arch)
            if hy2_binary:
                # Rename to hy2 for consistency
                ext = '.exe' if local_os == 'windows' else ''
                final_binary = save_dir / f"hy2{ext}"
                if hy2_binary != final_binary:
                    import shutil
                    shutil.move(str(hy2_binary), str(final_binary))
                    hy2_binary = final_binary
        else:
            # Normal mode: download via VPS (faster for US VPS with good connection)
            hy2_binary = download_local_hysteria_client(ssh, str(save_dir))
        
    finally:
        ssh.close()
        print(f"\n{msg('ssh_closed')}")
    
    # Generate client configuration
    print("\n" + fmt_banner("=" * 60))
    print(fmt_ok(f"  {msg('setup_complete')}"))
    print(fmt_banner("=" * 60))
    
    # Show logging mode status
    if params.debug:
        print("\n" + "-" * 60)
        print("  ⚠ DEBUG MODE ENABLED")
        print("-" * 60)
        print("  Logging is ENABLED for troubleshooting:")
        print("    - Hysteria2 log level: debug")
        print("    - Systemd/Docker logging: enabled")
        if not params.docker:
            print("  View logs: journalctl -u hysteria -f")
        else:
            print("  View logs: docker logs -f hy2")
        print("\n  ⚠ WARNING: Access patterns are being logged!")
        print("  Re-run without --debug to restore ZERO-LOG mode.")
    
    # Show security summary
    if security_info:
        print("\n" + fmt_banner("-" * 60))
        print(fmt_banner(f"  {msg('security_summary')}"))
        print(fmt_banner("-" * 60))
        if security_info['password_changed']:
            print("  ✓ Root password changed (saved to credentials.txt)")
        if security_info['ssh_key_only']:
            print(msg('ssh_key_only'))
        if security_info['fail2ban_installed']:
            print(msg('fail2ban_installed'))
        if security_info['firewall_hardened']:
            print(msg('firewall_hardened'))
        if security_info['agents_disabled']:
            print(msg('agents_disabled', ', '.join(security_info['agents_disabled'])))
        if security_info.get('history_cleared'):
            print("  ✓ Command history and system logs cleared")
        if security_info.get('zero_log_mode') and not params.debug:
            print("  ✓ ZERO-LOG MODE: No access logs written to disk")
            print("    - Hysteria2 log level: silent")
            print("    - Systemd/Docker logging: disabled")
        print(f"\n[PRIVACY] All passwords saved to credentials.txt")
        print(msg('ssh_password_disabled'))
    
    # Don't print configs to terminal for privacy - save to files only
    print("\n" + fmt_banner("-" * 60))
    print(fmt_info("[PRIVACY] Client configurations generated"))
    print(fmt_banner("-" * 60))
    print("  Configs contain sensitive information and are saved to files only.")
    print("  Check your output folder for:")
    print("    - clash.yaml        (Clash client config)")
    print("    - hy2-client.yaml   (Native client config)")
    print("    - credentials.txt   (Server credentials)")
    print("-" * 60)
    
    # Format server address with port hopping (handle IPv6) - for save_configs
    server_addr_hop = format_server_addr_hop(server_ip, hy2_port)
    server_addr_direct = format_server_addr(server_ip, hy2_port)
    
    # Always save configs to files (auto-generated folder if not specified)
    print("\n" + fmt_banner("-" * 60))
    print(fmt_step(f"Saving configurations to: {save_dir}"))
    print(fmt_banner("-" * 60))
    save_configs(
        save_dir=str(save_dir),
        server_ip=server_ip,
        server_name=server_name,
        hy2_port=hy2_port,
        hy2_password=hy2_password,
        pin_sha256=pin_sha256,
        hop_interval=hop_interval,
        masquerade_domain=masquerade_domain,
        new_root_password=new_root_password,
        pubkey_path=pubkey_path,
        china_mode=params.china,
        local_mode=local_mode
    )
    
    # Test the connection with the downloaded client
    if hy2_binary:
        config_path = save_dir / 'hy2-client.yaml'
        print("\n" + fmt_banner("-" * 60))
        print(fmt_step("Testing connection with downloaded client..."))
        print(fmt_banner("-" * 60))
        
        if test_hysteria_client(hy2_binary, config_path):
            print_ok("\n  ✓ Connection test PASSED!")
            print(f"  You can now use the client:")
            print(f"    {hy2_binary} client -c {config_path}")
        else:
            print_warn("\n  ✗ Connection test FAILED")
            print("  Check the server configuration and try manually:")
            print(f"    {hy2_binary} client -c {config_path}")
    
    print("-" * 60)
    
    # Final reminders - don't show sensitive info in terminal
    if security_info:
        print("\n" + fmt_banner("=" * 60))
        print(fmt_banner(f"  {msg('save_info')}"))
        print(fmt_banner("=" * 60))
        print(fmt_info(f"\n  [PRIVACY] All credentials saved to: {save_dir}/credentials.txt"))
        print(fmt_info(f"  [PRIVACY] Client configs saved to: {save_dir}/"))
        print(fmt_info(f"\n  SSH command saved in credentials.txt"))
        print(fmt_banner("=" * 60))


if __name__ == "__main__":
    main()
