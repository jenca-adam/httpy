#!/usr/bin/env python3
import http2, http2.proto
import time
import uuid
import hashlib

conn = http2.Connection("httpbin.org", 443)

print(conn.start())
print(conn.settings.server_settings)
while True:
    sender = http2.proto.HTTP2Sender(
        b"GET",
        {uuid.uuid4().hex: uuid.uuid4().hex},
        b"",
        "/get",
        "httpbin.org",
        conn,
    )
    streamid = sender.send()
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
