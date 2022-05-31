import unittest
import shutil
import importlib
import pathlib
import warnings
import sys
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
    httpy.set_debug()
except:
    httpy=None
def test_HTTPy_imports():
    import httpy
def test_http_200_ok():
    resp = httpy.request('http://httpbin.org/')
    assert resp.status==200
def test_https_200_ok():
    resp = httpy.request('https://python.org/')
    assert resp.status==200
def test_httpy_redirect_limit():
    with pytest.raises(httpy.TooManyRedirectsError):
        httpy.request('http://httpbin.org/redirect/8389382902',redirlimit=5)
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
                assert httpy.request(f'https://httpbin.org/status/{code}').status==int(code)
def test_httpy_post_raw():
    f=httpy.request('https://www.httpbin.org/post',method="POST",body="12345")
    assert f.json['data']=="12345"
def test_httpy_post_form():
    f=httpy.request('https://www.httpbin.org/post',method="POST",body={"foo":"bar"})
    assert f.json['form']=={"foo":"bar"}

with warnings.catch_warnings():
    unittest.main(argv=['first-arg-is-ignored'],exit=False,warnings='ignore')

