from . import (
    async_gather_tests,
    async_request_tests,
    async_rr_tests,
    async_tests,
    proto_tests,
)
import asyncio


async def run():
    for test_case in [
        async_gather_tests,
        async_request_tests,
        async_rr_tests,
        async_tests,
        proto_tests,
    ]:
        (await test_case.test())
