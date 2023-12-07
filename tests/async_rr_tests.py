#!/usr/bin/env python3
from httpy.httpy import _async_raw_request
import asyncio
async def main():
    return await asyncio.gather(

       *( _async_raw_request(
            "www.google.com", 443, "/", "https", debug=True, enable_cache=False) for _ in range(5))
    )
print(
        *map(lambda x:x.content,asyncio.run(main()))
)
