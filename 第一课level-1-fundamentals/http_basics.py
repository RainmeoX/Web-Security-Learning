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