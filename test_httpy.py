import unittest
import shutil
import importlib
import pathlib
import warnings
import sys
import time
import os
import pytest
try: import alive_progress
except:
    alive_progress=None
warnings.filterwarnings('ignore')
try:
    shutil.rmtree(pathlib.Path.home() / ".cache/httpy")
except :
    pass
try:
    
    import httpy
except:
    httpy=None
def test_HTTPy_imports():
    import httpy
def test_http_200_ok():
    resp = httpy.request('http://httpbin.org/',enable_cache=False)
    assert resp.status==200
def test_https_200_ok():
    resp = httpy.request('https://python.org/',enable_cache=False)
    assert resp.status==200
def test_httpy_nonblocking():
    t=time.time()
    resps=[httpy.request("https://httpbin.org/delay/1",blocking=False) for i in range(4)]
    assert time.time()-t<1
    for i in resps:
        i.wait()
        assert i.response.ok
def test_httpy_redirect_limit():
    with pytest.raises(httpy.TooManyRedirectsError):
        httpy.request('http://httpbin.org/redirect/8389382902',redirlimit=5,enable_cache=False)
def test_httpy_cache():
    httpy.request("https://example.net/")
    assert httpy.request("https://example.net/").fromcache
def test_httpy_get_status_codes(capsys):
    httpy.set_debug(False)
    with capsys.disabled():
        iterator=httpy.STATUS_CODES
        if alive_progress:
            iterator=alive_progress.alive_it(iterator)
        print()
        for code in iterator:
            if 400<=int(code):
                assert httpy.request(f'https://httpbin.org/status/{code}',enable_cache=False).status==int(code)
def test_httpy_post_raw():
    f=httpy.request('https://www.httpbin.org/post',method="POST",body="12345",enable_cache=False)
    assert f.json['data']=="12345"
def test_httpy_post_form():
    f=httpy.request('https://www.httpbin.org/post',method="POST",body={"foo":"bar"},enable_cache=False)
    assert f.json['form']=={"foo":"bar"}
def test_httpy_websocket_string():
    wsk = httpy.WebSocket('wss://echo.websocket.events',debug=True)
    wsk.send("Hello")
    assert wsk.recv()=="Hello"
def test_httpy_websocket_bytes():
    wsk = httpy.WebSocket('wss://echo.websocket.events',debug=True)
    wsk.send(b"World")
    assert wsk.recv()==b"World"
def test_httpy_websocket_string_long():
    wsk = httpy.WebSocket('wss://echo.websocket.events',debug=True)
    wsk.send("bla bla bla"*20)
    assert wsk.recv()=="bla bla bla"*20
def test_httpy_websocket_bytes_long():
    wsk = httpy.WebSocket('wss://echo.websocket.events',debug=True)
    a=os.urandom(500)
    wsk.send(a)
    assert wsk.recv()==a
def test_httpy_websocket_bytes_supalong():
    wsk = httpy.WebSocket('wss://echo.websocket.events',debug=True)
    a=os.urandom(65537)
    wsk.send(a)
    time.sleep(1)
    assert wsk.recv()==a
with warnings.catch_warnings():
    unittest.main(argv=['first-arg-is-ignored'],exit=False,warnings='ignore')

