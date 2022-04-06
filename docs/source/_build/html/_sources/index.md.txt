# httpy
A Python lightweight socket-based library to create HTTP(s) connections.
## Features
   * Cookies support
   * Caching support
   * Easy debugging
   * HTTP authentication
   * Form support
## Requirements
   * Python>=3.6
## Usage
It's easy.
```{code-block} python
---
lineno-start: 1
---
import httpy
resp = httpy.request("https://example.com/") # Do a request
resp.content #Access content
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

send:
GET / HTTP/1.1
Accept-Encoding: gzip, deflate, identity
Host: example.com
User-Agent: httpy/1.0.2
Connection: keep-alive

response: 
HTTP/1.1 200 OK

Content-Encoding: gzip
Age: 587058
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Wed, 06 Apr 2022 11:01:09 GMT
Etag: "3147526947+ident+gzip"
Expires: Wed, 13 Apr 2022 11:01:09 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (dcb/7F18)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 648
<Response [200 OK] (https://example.com/)>
```
