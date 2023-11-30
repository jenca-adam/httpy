#!/usr/bin/env python3
from httpy import http2,debugger
import asyncio

async def main():
    a = http2.connection.AsyncConnection("www.google.com", 443, debugger)
    await a.start()
    st = a.create_stream()
    print(st.streamid)
    hf = http2.frame.HeadersFrame(
        a.client_hpack.encode_headers(
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
    await st.send_frame(hf)
    while True:
        n = await st.recv_frame(True)
        print("recv on s1:", n)

        if isinstance(n, http2.frame.HeadersFrame):
            print(n.decoded_headers)
        elif isinstance(n, http2.frame.DataFrame):
            print(n.payload)
        elif isinstance(n, http2.frame.GoAwayFrame) or (n is None):
            break

asyncio.run(main())
