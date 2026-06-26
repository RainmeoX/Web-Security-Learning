#!/usr/bin/env python3
"""
第六课：文件上传漏洞 - 漏洞演示应用
功能：包含多种文件上传漏洞的 Flask 应用（仅用于学习，切勿用于生产环境）
"""

from flask import Flask, request, render_template_string, redirect, url_for, send_from_directory
import os
import uuid

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ============ 漏洞1：无任何校验 ============
@app.route('/upload1', methods=['GET', 'POST'])
def upload_no_check():
    """没有任何校验，任意文件都能上传"""
    if request.method == 'POST':
        f = request.files['file']
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
        return '上传成功（无校验）'
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <button>上传（无校验）</button>
        </form>
    '''

# ============ 漏洞2：仅检查扩展名（黑名单） ============
@app.route('/upload2', methods=['GET', 'POST'])
def upload_blacklist():
    """黑名单校验，可被绕过"""
    BLACKLIST = ['.py', '.sh', '.exe', '.bat']
    if request.method == 'POST':
        f = request.files['file']
        filename = f.filename
        ext = os.path.splitext(filename)[1].lower()
        if ext in BLACKLIST:
            return '禁止上传此类型文件'
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return f'上传成功（黑名单校验，扩展名：{ext}）'
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <button>上传（黑名单）</button>
        </form>
    '''

# ============ 漏洞3：仅检查 MIME 类型 ============
@app.route('/upload3', methods=['GET', 'POST'])
def upload_mime_only():
    """仅检查 Content-Type，可被篡改绕过"""
    ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/gif']
    if request.method == 'POST':
        f = request.files['file']
        if f.content_type not in ALLOWED_MIME:
            return '仅允许图片文件'
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))
        return f'上传成功（MIME校验，类型：{f.content_type}）'
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <button>上传（MIME校验）</button>
        </form>
    '''

# ============ 安全实现：白名单 + 内容检测 + 重命名 ============
@app.route('/upload_safe', methods=['GET', 'POST'])
def upload_safe():
    """安全实现：白名单 + 文件头检测 + 随机重命名"""
    ALLOWED_EXT = {'.jpg', '.jpeg', '.png', '.gif'}
    ALLOWED_MIME = {'image/jpeg', 'image/png', 'image/gif'}
    FILE_SIGNATURES = {
        b'\xff\xd8\xff': 'jpeg',
        b'\x89PNG': 'png',
        b'GIF8': 'gif',
    }
    if request.method == 'POST':
        f = request.files['file']
        filename = f.filename
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXT:
            return '扩展名不允许'
        if f.content_type not in ALLOWED_MIME:
            return 'MIME类型不允许'
        head = f.read(16)
        f.seek(0)
        if not any(head.startswith(sig) for sig in FILE_SIGNATURES):
            return '文件内容与类型不符（疑似图片马）'
        safe_name = str(uuid.uuid4()) + ext
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], safe_name))
        return f'安全上传成功，保存为：{safe_name}'
    return '''
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file">
            <button>安全上传</button>
        </form>
    '''

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    print("=== 文件上传漏洞演示 ===")
    print("访问以下路由查看不同校验方式：")
    print("  http://127.0.0.1:5000/upload1      - 无校验（最危险）")
    print("  http://127.0.0.1:5000/upload2      - 黑名单校验（可绕过）")
    print("  http://127.0.0.1:5000/upload3      - MIME校验（可篡改）")
    print("  http://127.0.0.1:5000/upload_safe  - 安全实现（白名单+内容检测）")
    app.run(debug=True, port=5000)
