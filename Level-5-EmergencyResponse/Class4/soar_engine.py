#!/usr/bin/env python3
"""
应急响应 第四课 练习4-4：SOAR 剧本编排引擎
功能：基于 YAML 配置的自动化应急响应剧本
应急响应阶段：自动化编排（SOAR）
"""

import yaml
import time
from datetime import datetime

# ============ 响应动作 ============
def block_ip(ip, firewall='iptables'):
    """封禁 IP"""
    print(f"  [动作] 封禁 IP: {ip}（通过 {firewall}）")
    # 实际执行: os.system(f'iptables -A INPUT -s {ip} -j DROP')
    return {'action': 'block_ip', 'ip': ip, 'status': 'success'}

def disable_account(account):
    """禁用账户"""
    print(f"  [动作] 禁用账户: {account}")
    # 实际执行: os.system(f'usermod -L {account}')
    return {'action': 'disable_account', 'account': account, 'status': 'success'}

def isolate_host(hostname):
    """隔离主机"""
    print(f"  [动作] 隔离主机: {hostname}（断开网络）")
    return {'action': 'isolate_host', 'host': hostname, 'status': 'success'}

def send_alert(message, channel='email'):
    """发送告警"""
    print(f"  [动作] 发送告警（{channel}）: {message}")
    return {'action': 'send_alert', 'message': message, 'status': 'sent'}

def run_script(script_path):
    """运行脚本"""
    print(f"  [动作] 运行脚本: {script_path}")
    return {'action': 'run_script', 'script': script_path, 'status': 'executed'}

def create_ticket(title, description):
    """创建工单"""
    print(f"  [动作] 创建工单: {title}")
    return {'action': 'create_ticket', 'title': title, 'status': 'created'}

# 动作映射表
ACTIONS = {
    'block_ip': block_ip,
    'disable_account': disable_account,
    'isolate_host': isolate_host,
    'send_alert': send_alert,
    'run_script': run_script,
    'create_ticket': create_ticket,
}

# ============ SOAR 引擎 ============
class SOAREngine:
    """SOAR 剧本编排引擎"""
    
    def __init__(self):
        self.playbooks = {}
        self.execution_log = []
    
    def load_playbook(self, yaml_content):
        """加载 YAML 格式的剧本"""
        playbook = yaml.safe_load(yaml_content)
        name = playbook.get('name', 'unnamed')
        self.playbooks[name] = playbook
        print(f"[+] 加载剧本: {name}")
        return playbook
    
    def trigger(self, playbook_name, alert_data):
        """触发剧本"""
        playbook = self.playbooks.get(playbook_name)
        if not playbook:
            print(f"[!] 剧本 {playbook_name} 不存在")
            return
        
        print(f"\n{'='*60}")
        print(f"[SOAR] 触发剧本: {playbook_name}")
        print(f"[SOAR] 触发时间: {datetime.now().isoformat()}")
        print(f"[SOAR] 告警数据: {alert_data}")
        print(f"{'='*60}")
        
        # 检查触发条件
        conditions = playbook.get('conditions', {})
        for key, expected in conditions.items():
            actual = alert_data.get(key)
            if actual != expected:
                print(f"[SOAR] 条件不匹配: {key}={actual} (期望 {expected})，剧本不执行")
                return
        
        print(f"[SOAR] 条件匹配，开始执行动作链...\n")
        
        # 执行动作链
        steps = playbook.get('steps', [])
        for i, step in enumerate(steps, 1):
            action_name = step.get('action')
            params = step.get('params', {})
            
            # 替换参数中的变量 {{alert.xxx}}
            for k, v in params.items():
                if isinstance(v, str) and '{{alert.' in v:
                    key = v.replace('{{alert.', '').replace('}}', '')
                    params[k] = alert_data.get(key, v)
            
            print(f"步骤 {i}/{len(steps)}: {step.get('name', action_name)}")
            action_func = ACTIONS.get(action_name)
            if action_func:
                result = action_func(**params)
                self.execution_log.append({
                    'playbook': playbook_name,
                    'step': i,
                    'action': action_name,
                    'result': result,
                    'timestamp': datetime.now().isoformat(),
                })
            else:
                print(f"  [!] 未知动作: {action_name}")
            
            # 步骤间延迟
            delay = step.get('delay', 0)
            if delay:
                print(f"  (等待 {delay} 秒)")
                time.sleep(delay)
        
        print(f"\n[SOAR] 剧本 {playbook_name} 执行完成")

# ============ 预定义剧本 ============
BRUTE_FORCE_PLAYBOOK = """
name: ssh_brute_force_response
description: SSH 暴力破解自动响应剧本
conditions:
  alert_type: ssh_brute_force
  severity: high
steps:
  - name: 封禁攻击IP
    action: block_ip
    params:
      ip: '{{alert.source_ip}}'
  - name: 发送告警通知
    action: send_alert
    params:
      message: '检测到SSH暴力破解，已自动封禁IP {{alert.source_ip}}'
      channel: email
  - name: 创建应急工单
    action: create_ticket
    params:
      title: 'SSH暴力破解事件 - {{alert.source_ip}}'
      description: '攻击目标: {{alert.target}}，失败次数: {{alert.count}}'
"""

RANSOMWARE_PLAYBOOK = """
name: ransomware_response
description: 勒索软件应急响应剧本
conditions:
  alert_type: ransomware
  severity: critical
steps:
  - name: 立即隔离受感染主机
    action: isolate_host
    params:
      hostname: '{{alert.target}}'
  - name: 禁用相关账户
    action: disable_account
    params:
      account: '{{alert.account}}'
  - name: 发送紧急告警
    action: send_alert
    params:
      message: '勒索软件告警！主机 {{alert.target}} 已隔离'
      channel: sms
  - name: 创建紧急工单
    action: create_ticket
    params:
      title: '勒索软件事件 - {{alert.target}}'
      description: '需要立即启动应急响应流程'
  - name: 运行取证脚本
    action: run_script
    params:
      script_path: '/opt/ir/collect_evidence.sh'
"""

if __name__ == '__main__':
    print("="*60)
    print("SOAR 剧本编排引擎")
    print("="*60)
    
    engine = SOAREngine()
    
    # 加载剧本
    print("\n--- 加载应急响应剧本 ---")
    engine.load_playbook(BRUTE_FORCE_PLAYBOOK)
    engine.load_playbook(RANSOMWARE_PLAYBOOK)
    
    # 模拟 SSH 暴力破解告警
    print("\n--- 场景1：SSH 暴力破解告警 ---")
    alert1 = {
        'alert_type': 'ssh_brute_force',
        'severity': 'high',
        'source_ip': '203.0.113.50',
        'target': 'prod-web-01',
        'count': 150,
    }
    engine.trigger('ssh_brute_force_response', alert1)
    
    # 模拟勒索软件告警
    print("\n--- 场景2：勒索软件告警 ---")
    alert2 = {
        'alert_type': 'ransomware',
        'severity': 'critical',
        'target': 'prod-db-02',
        'account': 'dbadmin',
    }
    engine.trigger('ransomware_response', alert2)
    
    # 执行日志
    print(f"\n{'='*60}")
    print(f"执行日志汇总（共 {len(engine.execution_log)} 个动作）")
    print(f"{'='*60}")
    for log in engine.execution_log:
        print(f"  {log['timestamp'][:19]} [{log['playbook']}] {log['action']}")
