import unittest
import shutil
import importlib
import pathlib
import warnings
import sys
import time
import os
import pytest
import asyncio

try:
    import alive_progress
except:
    alive_progress = None
warnings.filterwarnings("ignore")
try:
    shutil.rmtree(pathlib.Path.home() / ".cache/httpy")
except:
    pass
try:
    from .. import httpy
except:
    httpy = None
try:
    httpy.set_debug(False)
except:
    pass


def test_HTTPy_imports():
    from .. import httpy


def test_http_200_ok():
    resp = httpy.request("http://httpbin.org/", http_version="1.1", enable_cache=False)
    assert resp.status == 200


def test_https_200_ok():
    resp = httpy.request("https://python.org/", http_version="1.1", enable_cache=False)
    assert resp.status == 200


def test_httpy_nonblocking():
    t = time.time()
    resps = [
        httpy.request("https://httpbin.org/delay/1", blocking=False, http_version="2")
        for i in range(4)
    ]
    assert time.time() - t < 1
    for i in resps:
        i.wait()
        assert i.response.ok


def test_httpy_auth_basic():
    httpy.request("http://httpbin.org/basic-auth/root/pass/", auth=("root", "pass"))


def test_httpy_redirect_limit():
    with pytest.raises(httpy.TooManyRedirectsError):
        httpy.request("http://httpbin.org/redirect/8", redirlimit=5, enable_cache=False)


def test_httpy_cache():
    httpy.request("https://example.net/")
    assert httpy.request("https://example.net/").fromcache


def test_httpy_get_status_codes(capsys):
    httpy.set_debug(False)
    with capsys.disabled():
        iterator = httpy.STATUS_CODES
        if alive_progress:
            iterator = alive_progress.alive_it(iterator)
        for code in iterator:
            if 400 <= int(code):
                assert httpy.request(
                    f"https://httpbin.org/status/{code}", enable_cache=False
                ).status == int(code)


def test_httpy_http_1_post_raw():
    f = httpy.request(
        "https://www.httpbin.org/post",
        method="POST",
        body="12345",
        enable_cache=False,
        http_version="1.1",
    )
    assert f.json["data"] == "12345"


def test_httpy_http_1_post_form():
    f = httpy.request(
        "https://www.httpbin.org/post",
        method="POST",
        body={"foo": "bar"},
        enable_cache=False,
        http_version="1.1",
    )
    assert f.json["form"] == {"foo": "bar"}


def test_httpy_websocket_string():
    wsk = httpy.WebSocket("wss://echo.websocket.events")
    wsk.send("Hello")
    assert wsk.recv() == "Hello"


def test_httpy_websocket_bytes():
    wsk = httpy.WebSocket("wss://echo.websocket.events")
    wsk.send(b"World")
    assert wsk.recv() == b"World"


def test_httpy_websocket_string_long():
    wsk = httpy.WebSocket("wss://echo.websocket.events")
    wsk.send("bla bla bla" * 20)
    assert wsk.recv() == "bla bla bla" * 20


def test_httpy_websocket_bytes_long():
    wsk = httpy.WebSocket("wss://echo.websocket.events")
    a = os.urandom(500)
    wsk.send(a)
    assert wsk.recv() == a


def test_httpy_websocket_bytes_supalong():
    wsk = httpy.WebSocket("wss://echo.websocket.events")
    a = os.urandom(65537)
    wsk.send(a)
    time.sleep(1)
    assert wsk.recv() == a


def test_httpy_http2_sync():
    assert (
        httpy.request(
            "https://www.example.org/", http_version="2", enable_cache=False
        ).status
        == 200
    )


@pytest.mark.asyncio
async def test_httpy_http2_async():
    assert (
        await httpy.async_request(
            "https://www.example.org/", http_version="2", enable_cache=False
        )
    ).status == 200
