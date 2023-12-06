#!/usr/bin/env python3
from httpy import http2
from httpy.debugger import _Debugger
import asyncio

async def do_request():
    print("run")
    connection = http2.connection.AsyncConnection("www.example.com",443,_Debugger(True))
    await connection.start()
    sender = http2.proto.AsyncHTTP2Sender("GET",{},b"","/",_Debugger(True),"www.example.com")
    streamid = await sender.send(connection)
    rd = await http2.proto.AsyncHTTP2Recver()(connection,streamid)
    print(rd)
async def main():
    await asyncio.gather(*(do_request() for _ in range(50)))
asyncio.run(main())
