#!/usr/bin/env python3
"""
应急响应 第三课 练习3-1：ATT&CK 攻击链映射器
功能：将检测到的告警映射到 MITRE ATT&CK 战术，重建攻击链
应急响应阶段：分析（Analysis）+ 溯源（Attribution）
"""

from datetime import datetime
import json

# ATT&CK 战术映射（简化版）
ATTACK_TACTICS = {
    'reconnaissance': {
        'name': '侦察',
        'techniques': {
            'T1595': '主动扫描',
            'T1592': '收集目标主机信息',
            'T1589': '收集目标身份信息',
        }
    },
    'initial_access': {
        'name': '初始访问',
        'techniques': {
            'T1190': '利用面向公众的应用',
            'T1078': '有效账户',
            'T1133': '外部远程服务',
        }
    },
    'execution': {
        'name': '执行',
        'techniques': {
            'T1059': '命令和脚本解释器',
            'T1106': '原生API',
            'T1053': '计划任务/作业',
        }
    },
    'persistence': {
        'name': '持久化',
        'techniques': {
            'T1547': '引导或登录自动启动',
            'T1136': '创建账户',
            'T1543': '系统服务',
        }
    },
    'lateral_movement': {
        'name': '横向移动',
        'techniques': {
            'T1021': '远程服务',
            'T1072': '软件部署工具',
            'T1550': '替代认证材料',
        }
    },
    'exfiltration': {
        'name': '数据渗出',
        'techniques': {
            'T1041': '通过C2通道渗出',
            'T1567': '通过Web服务渗出',
            'T1052': '通过物理介质渗出',
        }
    },
    'impact': {
        'name': '影响',
        'techniques': {
            'T1486': '数据加密以影响（勒索软件）',
            'T1485': '数据破坏',
            'T1498': '网络拒绝服务',
        }
    },
}

class AttackChainMapper:
    """ATT&CK 攻击链映射器"""
    
    def __init__(self):
        self.alerts = []
        self.attack_chain = []
    
    def add_alert(self, timestamp, tactic, technique_id, description, source_ip='', target=''):
        """添加一个告警"""
        alert = {
            'timestamp': timestamp,
            'tactic': tactic,
            'technique_id': technique_id,
            'technique_name': ATTACK_TACTICS.get(tactic, {}).get('techniques', {}).get(technique_id, '未知'),
            'description': description,
            'source_ip': source_ip,
            'target': target,
        }
        self.alerts.append(alert)
    
    def build_chain(self):
        """按时间顺序重建攻击链"""
        self.attack_chain = sorted(self.alerts, key=lambda x: x['timestamp'])
        return self.attack_chain
    
    def analyze(self):
        """分析攻击链"""
        if not self.attack_chain:
            self.build_chain()
        
        print("\n" + "="*60)
        print("ATT&CK 攻击链分析报告")
        print("="*60)
        
        # 攻击概览
        tactics_used = set(a['tactic'] for a in self.attack_chain)
        print(f"\n攻击时间跨度: {self.attack_chain[0]['timestamp']} → {self.attack_chain[-1]['timestamp']}")
        print(f"涉及战术数: {len(tactics_used)}")
        print(f"告警总数: {len(self.attack_chain)}")
        
        # 攻击链详情
        print(f"\n{'='*60}")
        print("攻击链时间线")
        print(f"{'='*60}")
        for i, alert in enumerate(self.attack_chain, 1):
            tactic_name = ATTACK_TACTICS.get(alert['tactic'], {}).get('name', alert['tactic'])
            print(f"\n[{i}] {alert['timestamp']}")
            print(f"    战术: {tactic_name} ({alert['tactic']})")
            print(f"    技术: {alert['technique_id']} - {alert['technique_name']}")
            print(f"    描述: {alert['description']}")
            if alert['source_ip']:
                print(f"    源IP: {alert['source_ip']}")
            if alert['target']:
                print(f"    目标: {alert['target']}")
        
        # 战术覆盖
        print(f"\n{'='*60}")
        print("ATT&CK 战术覆盖")
        print(f"{'='*60}")
        for tactic in ATTACK_TACTICS:
            name = ATTACK_TACTICS[tactic]['name']
            count = sum(1 for a in self.attack_chain if a['tactic'] == tactic)
            mark = '✓' if count > 0 else ' '
            print(f"  [{mark}] {tactic:20s} {name:10s} ({count} 个告警)")
        
        # 防御建议
        print(f"\n{'='*60}")
        print("防御建议")
        print(f"{'='*60}")
        if 'reconnaissance' in tactics_used:
            print("  - 部署 IDS/IPS 检测扫描行为")
        if 'initial_access' in tactics_used:
            print("  - 修补面向公众应用的漏洞")
            print("  - 加强账户认证（MFA）")
        if 'persistence' in tactics_used:
            print("  - 检查启动项、计划任务、服务")
        if 'lateral_movement' in tactics_used:
            print("  - 网络分段，限制横向移动")
        if 'exfiltration' in tactics_used:
            print("  - 部署 DLP 监控数据外传")
        if 'impact' in tactics_used:
            print("  - 定期备份，测试恢复流程")

if __name__ == '__main__':
    print("="*60)
    print("ATT&CK 攻击链映射器")
    print("="*60)
    
    mapper = AttackChainMapper()
    
    # 模拟一次完整攻击的告警
    print("\n[*] 加载模拟攻击告警...")
    mapper.add_alert('2026-01-15 10:00', 'reconnaissance', 'T1595', '检测到端口扫描', '203.0.113.50', 'Web服务器')
    mapper.add_alert('2026-01-15 10:15', 'initial_access', 'T1190', 'Web应用SQL注入成功', '203.0.113.50', 'Web服务器')
    mapper.add_alert('2026-01-15 10:20', 'execution', 'T1059', '执行恶意命令 whoami', '203.0.113.50', 'Web服务器')
    mapper.add_alert('2026-01-15 10:30', 'persistence', 'T1547', '创建计划任务维持访问', '203.0.113.50', 'Web服务器')
    mapper.add_alert('2026-01-15 11:00', 'lateral_movement', 'T1021', '通过SSH横向移动到数据库服务器', 'Web服务器', '数据库服务器')
    mapper.add_alert('2026-01-15 11:30', 'exfiltration', 'T1041', '数据库数据通过C2通道外传', '数据库服务器', '外部C2')
    mapper.add_alert('2026-01-15 12:00', 'impact', 'T1486', '勒索软件加密文件', '数据库服务器', '所有文件')
    
    mapper.analyze()
