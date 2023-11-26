#!/usr/bin/env python3
from httpy import http2


test_goaway = False
# test_goaway=True
a = http2.connection.Connection("www.google.com", 443)
a.start()
st = a.create_stream()
print(st.streamid)
hf = http2.frame.HeadersFrame(
    a.hpack.encode_headers(
        {
            ":path": "/search?q=en+passant",
            ":method": "GET",
            ":scheme": "http",
            ":authority": "www.google.com",
        }
    ),
    end_headers=True,
    end_stream=True,
)
st.send_frame(hf)
if test_goaway:
    a.socket.sendall(b"\x00" * 60)
while True:
    n = st.recv_frame(True)
    print("recv on s1:", n)

    if isinstance(n, http2.frame.HeadersFrame):
        print(n.decoded_headers)
    elif isinstance(n, http2.frame.DataFrame):
        print(n.payload)
    elif isinstance(n, http2.frame.GoAwayFrame) or (n is None):
        break
