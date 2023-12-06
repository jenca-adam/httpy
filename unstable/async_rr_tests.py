#!/usr/bin/env python3
from httpy.httpy import _async_raw_request
import asyncio

print(
    asyncio.run(
        _async_raw_request(
            "www.google.com", 443, "/", "https", debug=True, enable_cache=False
        )
    ).content
)
