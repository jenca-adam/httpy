#!/usr/bin/env python3
import http2, http2.proto
import time
import uuid
import hashlib
conn = http2.Connection("strana-smer.sk", 443)

print(conn.start())
print(conn.settings.server_settings)
while True:
    sender = http2.proto.HTTP2Sender(
        b"GET",
        {"test_header": "header_testr" + uuid.uuid4().hex * 6},
        b"",
        "/",
        "strana-smer.sk",
        conn,
    )
    streamid = sender.send()
    print("STREAMID", streamid)
    print("WINDOW", conn.window.size)
    status,headers,body,_ = http2.proto.HTTP2Recver()(conn, streamid)
    print("STAT",status)
    print(headers)
    print("RESP HASH", hashlib.md5(body).hexdigest())
conn.close()
# time.sleep(.5)
# while True:pass
