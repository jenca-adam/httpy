#!/usr/bin/env python3
from httpy.httpy import _async_raw_request
import asyncio


async def test():
    q = await asyncio.gather(
        *(
            _async_raw_request(
                "www.google.com", 443, "/", "https", debug=True, enable_cache=False
            )
            for _ in range(5)
        )
    )
    await close_all_h2_connections()
    return q


if __name__ == "__main__":
    print(*map(lambda x: x.content, asyncio.run(test())))
