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
