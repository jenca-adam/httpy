from . import async_request_tests, async_rr_tests, async_stream_test


async def run():
    for test_case in [
        async_request_tests,
        async_rr_tests,
        async_stream_test,
    ]:
        print("TESTING", test_case)
        (await test_case.test())
