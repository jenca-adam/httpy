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
    return q


if __name__ == "__main__":
    asyncio.run(test())
