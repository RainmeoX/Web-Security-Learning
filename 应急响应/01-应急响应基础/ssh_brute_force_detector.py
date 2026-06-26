#!/usr/bin/env python3
"""
应急响应 第一课 练习1：SSH 暴力破解检测器
功能：解析 auth.log，识别暴力破解攻击 IP
应急响应阶段：检测（Detection）
"""

import re
from collections import defaultdict
from datetime import datetime

def parse_auth_logs(log_file='auth.log', threshold=10):
    """
    解析认证日志，提取失败登录尝试
    返回超过阈值的 IP 列表
    """
    failed_attempts = defaultdict(list)
    
    # 匹配 SSH 失败登录的正则
    pattern = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    )
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    timestamp = match.group(1)
                    ip = match.group(2)
                    failed_attempts[ip].append(timestamp)
    except FileNotFoundError:
        print(f"[!] 日志文件 {log_file} 不存在")
        print("[*] 生成模拟日志用于演示...")
        return generate_demo_log()
    
    # 筛选超过阈值的 IP
    attackers = {ip: times for ip, times in failed_attempts.items() if len(times) >= threshold}
    return attackers, failed_attempts

def generate_demo_log():
    """生成模拟的 auth.log 用于演示"""
    import random
    demo_log = 'auth_demo.log'
    attacker_ip = f"192.168.1.{random.randint(100,200)}"
    normal_ip = "10.0.0.5"
    
    with open(demo_log, 'w') as f:
        # 正常登录失败（少量）
        for i in range(3):
            f.write(f"Jan 15 10:{i:02d}:00 server sshd[1234]: Failed password for root from {normal_ip} port 22\n")
        # 暴力破解（大量）
        for i in range(50):
            f.write(f"Jan 15 11:{i:02d}:00 server sshd[1234]: Failed password for root from {attacker_ip} port 22\n")
    
    print(f"[+] 模拟日志已生成: {demo_log}")
    print(f"[+] 攻击者 IP: {attacker_ip}（50次失败）")
    print(f"[+] 正常 IP: {normal_ip}（3次失败）")
    return parse_auth_logs(demo_log, threshold=10)

def report(attackers, all_attempts):
    """生成检测报告"""
    print("\n" + "="*50)
    print("SSH 暴力破解检测报告")
    print("="*50)
    
    if not attackers:
        print("[OK] 未检测到暴力破解攻击")
        return
    
    print(f"[!] 检测到 {len(attackers)} 个攻击源 IP：\n")
    for ip, times in sorted(attackers.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  IP: {ip}")
        print(f"  失败次数: {len(times)}")
        print(f"  首次: {times[0]}")
        print(f"  末次: {times[-1]}")
        print(f"  建议: 立即封禁该 IP，检查 root 密码强度\n")

if __name__ == '__main__':
    print("="*50)
    print("SSH 暴力破解检测器")
    print("="*50)
    print("应急响应阶段：检测（Detection）")
    print()
    
    import sys
    log_file = sys.argv[1] if len(sys.argv) > 1 else 'auth.log'
    attackers, all_attempts = parse_auth_logs(log_file, threshold=10)
    report(attackers, all_attempts)
