#!/usr/bin/env python3
from httpy.httpy import async_request
import asyncio


async def test():
    stream = await async_request("https://example.com/", stream=True, debug=True)
    output = bytearray()
    while True:
        byte = await stream.read(1)
        print(byte)
        if not byte:
            break
        output.extend(byte)
    return output


if __name__ == "__main__":
    print(asyncio.run(test()))
