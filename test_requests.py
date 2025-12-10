import requests
r = requests.get("https://httpbin.org/get", timeout=10)
print("status:", r.status_code)
print("headers:", r.headers.get("Content-Type"))
print("origin:", r.json().get("origin"))
