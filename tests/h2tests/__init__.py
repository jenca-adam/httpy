from . import (
    async_request_tests,
    async_rr_tests,
)
import asyncio


async def run():
    for test_case in [
        async_request_tests,
        async_rr_tests,
    ]:
        print("TESTING", test_case)
        (await test_case.test())
