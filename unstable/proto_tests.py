#!/usr/bin/env python3
from httpy import http2
import httpy.httpy
import time
import uuid
import hashlib

conn = http2.Connection("httpbin.org", 443, httpy.httpy._Debugger(True))

print(conn.start())
print(conn.settings.server_settings)
while True:
    sender = http2.proto.HTTP2Sender(
        b"GET",
        {uuid.uuid4().hex: uuid.uuid4().hex},
        b"",
        "/get",
        "httpbin.org",
    )
    streamid = sender.send(conn)
    print("STREAMID", streamid)
    print("WINDOW", conn.window.size)
    status, headers, body, _ = http2.proto.HTTP2Recver()(conn, streamid)
    print("STAT", status)
    print(headers)
    print("RESP HASH", hashlib.md5(body).hexdigest())
    print("resp", body)
conn.close()
# time.sleep(.5)
# while True:pass
