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

