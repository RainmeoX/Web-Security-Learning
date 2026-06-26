#!/usr/bin/env python3
"""
第七课：代码审计 - 文件上传漏洞审计工具
功能：扫描 Python 代码中的文件上传漏洞
"""

import os
import re
import ast

# 危险模式：文件上传相关的危险函数
DANGEROUS_PATTERNS = [
    # request.files 相关
    (r'request\.files\[', '文件上传入口，需检查后续校验'),
    (r'\.save\s*\(', '文件保存操作，需检查路径和文件名'),
    # 路径拼接
    (r'os\.path\.join\s*\(.*filename', '路径拼接使用用户输入，可能路径穿越'),
    (r'open\s*\(.*request\.', '用用户输入打开文件，可能路径穿越'),
    # 执行用户上传内容
    (r'exec\s*\(.*open', '执行文件内容，RCE 风险'),
    (r'eval\s*\(.*open', '执行文件内容，RCE 风险'),
    (r'import\s+os.*os\.system', '系统命令执行，需检查输入来源'),
    (r'subprocess\.(call|run|Popen)', '子进程执行，需检查参数'),
    # 不安全的校验
    (r'splitext.*\[1\].*in\s*\[', '黑名单校验，建议改白名单'),
    (r'content_type.*in\s*\[', '仅 MIME 校验，可被篡改绕过'),
]

# 安全模式：好的校验实践
SAFE_PATTERNS = [
    (r'uuid\.uuid4', '随机重命名（好）'),
    (r'ALLOWED_EXT\s*=\s*\{', '白名单校验（好）'),
    (r'startswith.*b\'', '文件头魔数校验（好）'),
]

def audit_file(filepath):
    """审计单个 Python 文件"""
    print(f"\n{'='*60}")
    print(f"审计文件: {filepath}")
    print(f"{'='*60}")
    
    with open(filepath, encoding='utf-8') as f:
        content = f.read()
        lines = content.split('\n')
    
    issues = []
    safe_points = []
    
    # 检查危险模式
    for pattern, desc in DANGEROUS_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                issues.append((i, desc, line.strip()))
    
    # 检查安全模式
    for pattern, desc in SAFE_PATTERNS:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                safe_points.append((i, desc))
    
    # 输出结果
    if issues:
        print(f"\n[!] 发现 {len(issues)} 个潜在问题：")
        for line_no, desc, code in issues:
            print(f"  第{line_no}行 [{desc}]")
            print(f"    代码: {code}")
    else:
        print("\n[OK] 未发现明显危险模式")
    
    if safe_points:
        print(f"\n[+] 发现 {len(safe_points)} 个安全实践：")
        for line_no, desc in safe_points:
            print(f"  第{line_no}行 {desc}")
    
    return issues

def audit_directory(dirpath):
    """审计整个目录"""
    print(f"\n{'#'*60}")
    print(f"# 审计目录: {dirpath}")
    print(f"{'#'*60}")
    
    all_issues = {}
    for root, dirs, files in os.walk(dirpath):
        # 跳过 .git、虚拟环境等
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__', 'ir_env', 'venv')]
        for f in files:
            if f.endswith('.py'):
                filepath = os.path.join(root, f)
                issues = audit_file(filepath)
                if issues:
                    all_issues[filepath] = issues
    
    # 汇总
    print(f"\n{'='*60}")
    print(f"审计完成汇总")
    print(f"{'='*60}")
    print(f"审计文件数: {sum(1 for _ in os.walk(dirpath))}")
    print(f"有问题文件: {len(all_issues)}")
    total_issues = sum(len(v) for v in all_issues.values())
    print(f"总问题数: {total_issues}")
    
    if all_issues:
        print("\n问题分布：")
        for f, issues in all_issues.items():
            print(f"  {os.path.basename(f)}: {len(issues)} 个问题")

if __name__ == '__main__':
    # 审计当前目录
    target = input("输入要审计的目录（回车审计当前目录）: ").strip() or '.'
    audit_directory(target)
