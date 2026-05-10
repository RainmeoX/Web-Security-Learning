import requests

url = "http://127.0.0.1:5000/"
res = requests.get(url)

print("状态码:", res.status_code)
print("响应体:", res.text)