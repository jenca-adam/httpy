#!/usr/bin/env python3
from httpy import http2
from httpy.debugger import _Debugger
import asyncio

def main():
    connection = http2.connection.Connection("www.example.com",443,_Debugger(True))
    connection.start()
    sender = http2.proto.HTTP2Sender("GET",{},b"","/",_Debugger(True),"www.example.com")
    streamid = sender.send(connection)
    rd = http2.proto.HTTP2Recver()(connection,streamid)

main()
