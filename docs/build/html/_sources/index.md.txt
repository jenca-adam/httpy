# httpy
A Python lightweight socket-based library to create HTTP(s) and WebSocket connections.
## Features
   * Cookies support
   * Caching support
   * Easy debugging
   * HTTP Basic and Digest authentication
   * Form support
   * Keep-Alive and connection pooling support
   * JSON support
   * Sessions support
   * Runs in PyPy
   * Independent of http.client
## Requirements
   * Python>=3.6
## Usage
### HTTP

It's easy.
```{code-block} python
---
lineno-start: 1
---
import httpy
resp = httpy.request("https://example.com/") # Do a request
resp.content #Access content
```
#### Sessions
The `Session` class is there for you:
```{code-block} python
---
lineno-start: 1
---
import httpy
session = httpy.Session()
session.request("https://example.com/") # ...
```

### WebSocket
Easy again...
```{code-block} python
---
lineno-start: 1
---
>>> import httpy
>>> sock = httpy.WebSocket("wss://echo.websocket.events/")# create a websocket(echo server example)
>>> sock.send("Hello, world!💥")# you can send also bytes
>>> sock.recv()
"Hello, world!💥"
```

[API Documentation](httpy)
## Examples
### POST method
#### Simple Form
```{code-block} python
---
lineno-start: 1
---
import httpy
resp = httpy.request("https://example.com/", method="POST", body = {"foo":"bar"})
# ...
```
#### Sending files
```{code-block} python
---
lineno-start: 1
---
import httpy
resp = httpy.request("https://example.com/", method = "POST", body = { "foo" : "bar", "file" : httpy.File.open( "example.txt" ) })
# ...
```
#### Sending binary data
```{code-block} python
---
lineno-start: 1
---
import httpy
resp = httpy.request("https://example.com/", method = "POST", body= b" Hello, World ! ")
# ...
```
#### Sending plain text
```{code-block} python
---
lineno-start: 1
---
resp = httpy.request("https://example.com/", method = "POST", body = "I support Ünicode !")
# ...
```
#### Sending JSON
```{code-block} python
---
lineno-start: 1
---
resp = httpy.request("https://example.com/", method = "POST", body = "{\"foo\" : \"bar\" }", content_type = "application/json")
# ...
```
### Debugging
Just set `debug` to `True` :
```{code-block} python
>>> import httpy
>>> httpy.request("https://example.com/",debug=True)
[INFO][request](1266): request() called.
[INFO][_raw_request](1112): _raw_request() called.
[INFO][_raw_request](1113): Accessing cache.
[INFO][_raw_request](1120): No data in cache.
[INFO][_raw_request](1151): Establishing connection
[INFO]Connection[__init__](778): Created new Connection upon <socket.socket fd=3, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=6, laddr=('192.168.100.88', 58998), raddr=('93.184.216.34', 443)>

send:
GET / HTTP/1.1
Accept-Encoding: gzip, deflate, identity
Host: www.example.com
User-Agent: httpy/1.1.0
Connection: keep-alive

response: 
HTTP/1.1 200 OK

Content-Encoding: gzip
Age: 438765
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Wed, 13 Apr 2022 12:59:07 GMT
Etag: "3147526947+gzip"
Expires: Wed, 20 Apr 2022 12:59:07 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (dcb/7F37)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 648
<Response [200 OK] (https://www.example.com/)>
```
