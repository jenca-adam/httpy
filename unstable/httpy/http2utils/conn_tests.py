#!/usr/bin/env python3
import connection
import frame
test_goaway=False
#test_goaway=True
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
if test_goaway:a.socket.sendall(b'\x00'*60)
while True:
    n,cl=st.recv_frame()
    print("recv on s1:",n)
    if isinstance(n,frame.HeadersFrame):
        print(n.decoded_headers)
