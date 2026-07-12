import urllib.request, json
url='http://127.0.0.1:8000/api/register'
data={
 "full_name":"Test User",
 "email":"testuser@example.com",
 "phone":"1234567890",
 "password":"Password1!",
 "confirm_password":"Password1!",
 "role":"Administrator"
}
req=urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type':'application/json'})
try:
    resp=urllib.request.urlopen(req, timeout=10)
    print('STATUS', resp.getcode())
    print(resp.read().decode())
except Exception as e:
    try:
        from urllib.error import HTTPError
        if isinstance(e, HTTPError):
            print('HTTP', e.code, e.read().decode())
        else:
            print('ERR', e)
    except Exception:
        print('ERR', e)
