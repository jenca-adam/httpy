#!/usr/bin/env python3
from httpy import http2
from httpy.debugger import _Debugger
import asyncio


async def do_request():
    connection = http2.connection.AsyncConnection(
        "www.google.com", 443, _Debugger(True)
    )
    await connection.start()
    sender = http2.proto.AsyncHTTP2Sender(
        "GET", {}, b"", "/", _Debugger(True), "www.google.com"
    )
    streamid = await sender.send(connection)
    rd = await http2.proto.AsyncHTTP2Recver()(connection, streamid)
    return (rd)


async def test():
    return (await do_request())

if __name__=="__main__":
    asyncio.run(test())
