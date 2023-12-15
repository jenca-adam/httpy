#!/usr/bin/env python3
import httpy
import asyncio

async def perform_request():
    print("E")
    return (await httpy.async_request("https://www.example.com/",debug=True,enable_cache=False))

async def test():
    await httpy.initiate_http2_connection(host="www.example.com")
    return await asyncio.gather(*(perform_request() for _ in range(100)))

if __name__=="__main__":
    print(asyncio.run(test()))
