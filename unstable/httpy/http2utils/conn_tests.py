#!/usr/bin/env python3
import connection
import frame

a = connection.Connection("www.google.com", 443)
a.start()
st = a.create_stream()
hf = frame.HeadersFrame(
    a.hpack.encode_headers(
        {
            ":path": "/",
            ":method": "GET",
            ":scheme": "https",
            ":authority": "www.google.com",
        }
    ),
    end_headers=True,
    end_stream=True,
)
st.send_frame(hf)
while True:
    print(st.recv_frame())
