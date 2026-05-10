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