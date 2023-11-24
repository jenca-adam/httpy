#!/usr/bin/env python3
import http2, http2.proto
import time
import uuid
conn = http2.Connection("www.google.com",443)

print(conn.start())
print(conn.settings.server_settings)
while True:
    sender = http2.proto.HTTP2Sender(b'GET',{"test_header":"header_testr"+uuid.uuid4().hex*6},b'','/','www.google.com',conn)
    streamid = sender.send()
    print("STREAMID",streamid)
    print("WINDOW",conn.window.size)
    recver = http2.proto.HTTP2Recver()(conn,streamid)
conn.close()
#time.sleep(.5)
#while True:pass
