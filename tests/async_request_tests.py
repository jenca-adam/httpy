#!/usr/bin/env python3
import httpy
import asyncio

async def perform_request():
    return (await httpy.async_request("https://www.example.com/",debug=True,enable_cache=False))

async def test():
    await asyncio.gather(*(perform_request() for _ in range(10)))

if __name__=="__main__":
    print(asyncio.run(test()))
