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