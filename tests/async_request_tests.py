#!/usr/bin/env python3
import httpy
import asyncio

async def perform_request():
    print("start")
    print(await httpy.async_request("https://www.example.com/",debug=True,enable_cache=False))

async def main():
    await asyncio.gather(*(perform_request() for _ in range(10)))

asyncio.run(main())
