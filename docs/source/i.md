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

## Installation

### Any platform

#### Git
1. `git clone https://github.com/jenca-adam/httpy`
1. `cd httpy`
1. `python3 setup.py install`
The Python version check will be performed automatically

#### Pip

1. `python3 -m pip install httpy`

### Arch Linux

1. `yay -S httpy`
:warning: This is stuck on version 1.5.1 and probably won't be updated any time soon, because I am stupid and deleted my SSH key.

## Usage

### HTTP

It's easy.
```
import httpy
resp = httpy.request("https://example.com/") # Do a request
resp.content #Access content
```
#### Non-blocking requests
```
import httpy
pending = httpy.request("https://example.com/", blocking = False)
# PendingRequest.response returns the result of the response. You can check if the request is already done using PendingRequest.finished
```
#### Sessions
The `Session` class is there for you:
```
import httpy
session = httpy.Session()
session.request("https://example.com/") # ...
```

### WebSocket
Easy again...
```
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
```
import httpy
resp = httpy.request("https://example.com/", method="POST", body = {"foo":"bar"})
# ...
```
#### Sending files
```
import httpy
resp = httpy.request("https://example.com/", method = "POST", body = { "foo" : "bar", "file" : httpy.File.open( "example.txt" ) })
# ...
```
#### Sending binary data
```
import httpy
resp = httpy.request("https://example.com/", method = "POST", body= b" Hello, World ! ")
# ...
```
#### Sending plain text
```
resp = httpy.request("https://example.com/", method = "POST", body = "I support Ünicode !")
# ...
```
#### Sending JSON
```
resp = httpy.request("https://example.com/", method = "POST", body = "{\"foo\" : \"bar\" }", content_type = "application/json")
# ...
```
### Debugging
Just set `debug` to `True` :
```
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
