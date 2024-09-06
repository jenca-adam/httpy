import os
import time
import email.utils
import datetime
import gzip
import struct
import warnings

from .utils import *
from .errors import *
from .common import *
from .status import Status
from .headers import Headers


class ETag:
    """Class for HTTP ETags"""

    def __init__(self, s):
        self.weak = False
        if s.startswith("W/") or s.startswith("w/"):
            self.weak = True
        self.etag = s.replace('"', "")

    def __eq__(self, e):
        return self.etag == e.etag

    def __str__(self):
        if self.weak:
            return f'W/"{self.etag}"'
        return f'"{self.etag}"'

    def add_header(self, headers):
        """Appends this ETag in If-None-Match header."""
        if "If-None-Match" in headers:
            headers["If-None-Match"] += ", " + str(self)
        else:
            headers["If-None-Match"] = str(self)


class CacheControl:
    """Class for parsing Cache-Control HTTP Headers"""

    def __init__(self, directives):
        d = [_mk2l(x.split("=")) for x in directives.split(",")]
        self.directives = CaseInsensitiveDict(d)
        if "max-age" in self.directives:
            self.max_age = int(self.directives["max-age"])
            self.cache = True
        elif "no-cache" in self.directives:
            self.cache = False
            self.max_age = 0
        else:
            self.max_age = 0
            self.cache = True


class CacheFile:
    """HTTPy cache file parser"""

    def __init__(self, f):
        self.src = f
        file = gzip.GzipFile(f, "rb")
        tml = ord(file.read(1))
        self.time_cached = _unpk_float(file.read(tml))
        etl = ord(file.read(1))
        self.time_elapsed = _unpk_float(file.read(etl))
        srl = _int16unpk(file.read(2))
        sl = file.read(srl)
        self.status = Status(sl)
        if "\x01" in f:
            self.url = os.path.split(f)[-1].replace("\x01", "://").replace("\x02", "/")
            warnings.warn(
                OldCacheFileWarning(
                    f"cache file {f!r}  is in the old format(file name). \n Please, delete it to avoid further incompatibility problems"
                )
            )
        else:
            self.url = os.path.split(f)[-1].replace("\xfe", "://").replace("\xff", "/")
        method_desc = file.read(2)
        if method_desc != b"\150+":
            warnings.warn(
                OldCacheFileWarning(
                    f"cache file {f!r}  is in the old format(pre 1.5.0). \n Please, delete it to avoid further incompatibility problems"
                )
            )
            file.seek(file.tell() - 2)
        else:
            method_l = _int16unpk(file.read(2))
            self.method = file.read(method_l).decode()
        cfconfig = ord(file.read(1))
        self.expires = None
        if (not cfconfig & 0b1100000) or (cfconfig & 0x80):
            warnings.warn(
                OldCacheFileWarning(
                    f"cache file {f!r}  is in the old format(cache file config static bits don't match). \n Please, delete it to avoid further incompatibility problems"
                )
            )
            if cfconfig == 255:
                expires_length = ord(file.read(1))
                self.expires = _unpk_float(file.read(expires_length))

            self.http_version = "1.1"
            request_headers_present = False
        else:
            if cfconfig & 0b1:
                expires_length = ord(file.read(1))
                self.expires = _unpk_float(file.read(expires_length))
            http_version = (cfconfig & 0b11100) >> 2
            if http_version > 2:
                warnings.warn(
                    UserWarning(
                        f"cache file {f!r} has an unknown http version (ID: {http_version}), please update httpy to the newest version to gain compatibility with the cache file"
                    )
                )
                # fallback
                http_version = 2

            self.http_version = [None, "1.1", "2"][http_version]
            request_headers_present = cfconfig & 0b10
        if self.http_version is None:
            warnings.warn(
                OldCacheFileWarning(
                    f"cache file {f!r}  is in the old format. \n Please, delete it to avoid further incompatibility problems"
                )
            )
            file.seek(file.tell() - 1)

        if request_headers_present:
            request_headers_n_entries = _int16unpk(file.read(2))
            request_headers = []
            for _ in range(request_headers_n_entries):
                request_headers.append(read_until(file, b"\r"))
            self.request_headers = Headers(request_headers)
        self.content = file.read()
        file.seek(0)
        file.close()
        self.headers, self.body = self.content.split(b"\x00", 1)
        self.headers = Headers(self.headers.split(b"\r"))
        self.age = 0
        self.etag = None
        self.last_modified = None
        if "ETag" in self.headers:
            self.etag = ETag(self.headers["ETag"])
        if "last-modified" in self.headers:
            self.last_modified = self.headers["Last-Modified"]
        if "Age" in self.headers:
            self.age = int(self.headers["Age"])
        self.time_generated = self.time_cached - self.age
        if "Cache-Control" in self.headers:
            self.cache_control = CacheControl(self.headers["Cache-Control"])
        else:
            self.cache_control = CacheControl("no-cache")

    @property
    def expired(self):
        if self.expires is not None and self.expires < time.time():
            return True
        return time.time() - self.time_generated > self.cache_control.max_age

    def __repr__(self):
        return f"<CacheFile {self.url!r}>"

    def add_header(self, headers):
        """
        Adds If-None-Match and If-Modified-Since headers to request.

        :param  headers: Headers to add into
        """
        if self.etag:
            self.etag.add_header(headers)
        if self.last_modified:
            headers["if-modified-since"] = self.last_modified


class Cache:
    """
    Cache Class
    """

    def __init__(self, d=HTTPY_DIR / "default" / "sites"):
        if not os.path.exists(d):
            os.makedirs(d)
        self.dir = d
        self.files = []
        for f in os.listdir(d):
            try:
                self.files.append(CacheFile(os.path.join(d, f)))
            except:
                pass

    def updateCache(self):
        """Updates self.files according to /sites directory content and removes expired ones"""
        for file in self.files:
            if file.expired:
                os.remove(
                    os.path.join(
                        self.dir, file.url.replace("://", "\xfe").replace("/", "\xff")
                    )
                )
        self.files = [
            CacheFile(os.path.join(self.dir, i)) for i in os.listdir(self.dir)
        ]

    def __getitem__(self, t):
        u, m = t
        self.updateCache()  # ...
        for f in self.files:
            if reslash(f.url) == reslash(u) and f.method == m:
                return f
        return None

    def __contains__(self, u):
        return self[u] is not None


def cache_write(response, base_dir, expires_override=None):
    """
    Writes a response to cache

    :param response: the response to save
    :type response: Response"""
    debugger.info("cache_write  called")
    data = b""
    data += _binappendfloat(time.time())
    data += _binappendfloat(response._time_elapsed)
    data += _binappendstr(f"{response.status:03} {response.reason}")
    data += b"\150+"
    data += _binappendstr(response.method)
    if expires_override is not None:
        expires_tup = email.utils.parsedate(expires_override)
        if expires_tup is None:
            debugger.warn("wrong Expires header format!")
            has_expires = False
        else:
            expires = time.mktime(expires_tup)
            if expires < time.time():
                debugger.info("Expired Cache. Aborting cache_write.")
                return
            has_expires = True
            expires_bin = _binappendfloat(expires)
            # data += expires_bin
    else:
        has_expires = False
    cfconfig = (
        0b1100010
        | has_expires
        | [None, "1.1", "2"].index(response.request.http_version) << 2
    )
    data += struct.pack("B", cfconfig)
    if has_expires:
        data += expires_bin
    data += struct.pack(
        "!H", sum(1 for h in response.request.headers if not h.startswith(":"))
    )
    data += "\r".join(
        [
            mk_header(i)
            for i in filter(
                lambda x: not x[0].startswith(":"), response.request.headers.items()
            )
        ]
    ).encode()  # remove h2 hf
    data += b"\r"
    data += "\r".join([mk_header(i) for i in response.headers.headers.items()]).encode()
    data += b"\x00"
    data += response.content

    with open(
        base_dir / "sites" / (response.url.replace("://", "\xfe").replace("/", "\xff")),
        "wb",
    ) as f:
        f.write(gzip.compress(data))
