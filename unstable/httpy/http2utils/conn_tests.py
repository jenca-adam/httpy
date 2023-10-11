import connection
import frame

a = connection.Connection("www.google.com", 443)
a.start()
st = a.create_stream()
sf = a.socket.makefile("b")
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
print(hf.__dict__)
while True:
    a = frame.parse(sf)
    print(a, a.__dict__)
