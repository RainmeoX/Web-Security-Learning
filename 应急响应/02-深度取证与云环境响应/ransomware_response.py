#!/usr/bin/env python3
"""
应急响应 第二课 练习3：勒索软件应急响应 - 模拟与解密
功能：模拟勒索软件加密过程，并编写解密工具
应急响应阶段：取证（Forensics）+ 恢复（Recovery）

⚠️ 警告：仅用于学习，切勿用于非法用途
"""

import os
from cryptography.fernet import Fernet
import json
from datetime import datetime

class RansomwareSimulator:
    """勒索软件模拟器（仅用于学习应急响应）"""
    
    def __init__(self, target_dir='demo_files'):
        self.target_dir = target_dir
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.encrypted_files = []
        
        # 创建演示目录
        os.makedirs(target_dir, exist_ok=True)
    
    def create_demo_files(self):
        """创建演示用的文件"""
        demo_contents = {
            '重要文档.txt': '这是我的重要文档，包含敏感信息',
            '财务数据.txt': '账户余额：1000000',
            '密码.txt': '我的密码：password123',
            '日记.txt': '今天天气真好',
        }
        for name, content in demo_contents.items():
            with open(os.path.join(self.target_dir, name), 'w') as f:
                f.write(content)
        print(f"[+] 已创建 {len(demo_contents)} 个演示文件在 {self.target_dir}/")
    
    def encrypt_files(self):
        """模拟加密文件"""
        print(f"\n[!] 勒索软件启动，正在加密 {self.target_dir}/ ...")
        for filename in os.listdir(self.target_dir):
            filepath = os.path.join(self.target_dir, filename)
            if os.path.isfile(filepath) and not filename.endswith('.locked'):
                with open(filepath, 'rb') as f:
                    data = f.read()
                encrypted = self.cipher.encrypt(data)
                # 加密后文件名加 .locked 后缀
                locked_path = filepath + '.locked'
                with open(locked_path, 'wb') as f:
                    f.write(encrypted)
                # 删除原文件
                os.remove(filepath)
                self.encrypted_files.append(filename)
                print(f"  [加密] {filename} -> {filename}.locked")
        
        # 保存密钥（模拟攻击者保留密钥）
        with open('ransom_key.json', 'w') as f:
            json.dump({
                'key': self.key.decode(),
                'files': self.encrypted_files,
                'timestamp': datetime.now().isoformat(),
                'message': '你的文件已被加密，支付 1 BTC 解密'
            }, f, indent=2)
        print(f"\n[!] 加密完成！{len(self.encrypted_files)} 个文件被加密")
        print(f"[!] 密钥已保存到 ransom_key.json（模拟攻击者保留）")

class RansomwareDecryptor:
    """勒索软件解密工具（应急响应恢复阶段）"""
    
    def __init__(self, target_dir='demo_files', key_file='ransom_key.json'):
        self.target_dir = target_dir
        with open(key_file) as f:
            data = json.load(f)
        self.key = data['key'].encode()
        self.cipher = Fernet(self.key)
        self.encrypted_files = data['files']
    
    def decrypt_files(self):
        """解密所有文件"""
        print(f"\n[+] 应急响应：恢复阶段")
        print(f"[+] 正在解密 {self.target_dir}/ 下的文件...\n")
        
        recovered = 0
        for filename in os.listdir(self.target_dir):
            filepath = os.path.join(self.target_dir, filename)
            if filename.endswith('.locked'):
                with open(filepath, 'rb') as f:
                    encrypted_data = f.read()
                try:
                    decrypted = self.cipher.decrypt(encrypted_data)
                    # 恢复原文件名
                    original_path = filepath.replace('.locked', '')
                    with open(original_path, 'wb') as f:
                        f.write(decrypted)
                    os.remove(filepath)
                    print(f"  [恢复] {filename} -> {filename.replace('.locked','')}")
                    recovered += 1
                except Exception as e:
                    print(f"  [失败] {filename}: {e}")
        
        print(f"\n[+] 恢复完成！成功解密 {recovered} 个文件")
        return recovered

if __name__ == '__main__':
    print("="*50)
    print("勒索软件应急响应演练")
    print("="*50)
    
    # 阶段1：模拟攻击
    print("\n--- 阶段1：模拟勒索软件攻击 ---")
    simulator = RansomwareSimulator()
    simulator.create_demo_files()
    input("\n按回车键模拟勒索软件加密...")
    simulator.encrypt_files()
    
    # 阶段2：应急响应
    print("\n--- 阶段2：应急响应 - 文件恢复 ---")
    print("[*] 安全团队发现勒索软件，开始应急响应")
    print("[*] 找到密钥文件 ransom_key.json，开始解密...")
    input("按回车键开始解密恢复...")
    decryptor = RansomwareDecryptor()
    decryptor.decrypt_files()
    
    print("\n[+] 应急响应完成！文件已恢复")
    print("[*] 后续行动：")
    print("  1. 分析入侵路径（如何被植入勒索软件）")
    print("  2. 修补漏洞，防止再次入侵")
    print("  3. 备份恢复的文件")
    print("  4. 编写应急响应报告")
