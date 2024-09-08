#  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
#  HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
#  OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#  PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
#  IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
#  ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
"""
HTTPy is a lightweight socket-based HTTP and WebSocket client.
"""
import socket  # of course
import os  # for file manipulation
import re  # for parsing urls and statuses
import ssl  # for TLS encryption in HTTPS
import io  # for metaclass of File
import warnings  # to warn
import gzip  # to unpack
import zlib  # to unpack
import functools  # to decorate
import json  # to encode
import random  # to generate cnonces and boundaries
import string  # to generate cnonces and boundaries
import mimetypes  # to guess type of uploaded file
import pathlib  # to manipulate files
import math  # to encode ints
import base64  # for Basic auth
import email.utils  # to parse date strings
import datetime  # to parse date strings
import time  # to measure time
import struct  # to pack floats
import hashlib  # for Digest auth
import pickle  # to save data
import threading  # to create threads
import queue  # to communicate between threads
import builtins  # for debugging
import inspect  # for debugging
import sys  # for debugging
import asyncio  # for async requests
import atexit  # to add exit handlers

from . import http2
from .common import *
from .headers import Headers
from .utils import *
from .utils import _create_connection_and_handle_errors, is_closed
from .errors import *
from .status import *
from .alpn import alpn_negotiate
from .patterns import *
from .debugger import _Debugger
from .proto import HTTP11, HTTP2, _HTTP2Async
from .stream import Stream
from .response import Response
from .cache import *
from .ssl_context import generate_ssl_context

try:
    import chardet  # to detect charsets
except ImportError:
    chardet = None

os.makedirs(HTTPY_DIR / "dirs", exist_ok=True)
os.makedirs(HTTPY_DIR / "default" / "sites", exist_ok=True)
default_context = ssl._create_default_https_context()
default_context.set_alpn_protocols(["http/1.1", "h2"])
schemes = {"http": 80, "https": 443}


class Cookie:
    """
    Class for HTTP cookies
    """

    def __init__(self, name, value, attributes, host):
        self.name, self.value = name, value
        self.attributes = CaseInsensitiveDict(attributes)
        self.secure = "Secure" in self.attributes
        self.expires = self.attributes.get("Expires", None)
        if self.expires is not None:
            if isinstance(self.expires, str):
                self.expires = email.utils.parsedate_to_datetime(self.expires)
            else:
                self.expires = datetime.datetime.fromtimestamp(self.expires)
        self.path = self.attributes.get("Path", "/")
        self.host = self.attributes.get("domain", host)
        self._host = host
        self.samesite = self.attributes.get("samesite", "lax").lower()

    @property
    def expired(self):
        """Checks if cookie expired"""
        if self.expires is None:
            return False
        return time.time() >= self.expires.timestamp()

    def to_binary(self):
        """Converts cookie to binary representation"""
        data = _binappendstr(self.name + "=" + self.value)
        if self.host == self._host:
            data += b"\x00\x00"
        else:
            data += _binappendstr(self.host)
        data += _binappendstr(self.path)

        if self.secure:
            data += b"\x01"
        if self.expires:
            b = self.expires.timestamp()
            data += _binappendfloat(b)
        else:
            data += b"\x00"
        return data

    @classmethod
    def from_header(self, header, host):
        """Parses cookie header"""
        n = header.split(";")
        f = n[0].split("=", 1)
        if "" in n:
            n.remove("")
        attrs = (_mk2l([a.strip() for a in i.split("=")]) for i in n[1:])
        return Cookie(*f, attrs, host)

    def as_header(self):
        """Returns Set-Cookie Header"""
        return self.name + "=" + self.value

    @classmethod
    def from_binary(self, binary, host):
        """Creates cookie from binary representation"""
        buffer = io.BytesIO(binary)
        kvpl = _int16unpk(buffer.read(2))
        k, v = buffer.read(kvpl).split(b"=", 1)
        hostl = _int16unpk(buffer.read(2))
        data = {}
        if hostl > 0:
            data["Host"] = buffer.read(hostl).decode()
        pl = _int16unpk(buffer.read(2))
        p = buffer.read(pl)
        data["Path"] = p
        n = buffer.read(1)
        if n == b"\x01":
            data["Secure"] = True
            n = buffer.read(1)
        if n == b"\x00":
            expires = None
        else:
            tstamp = buffer.read(ord(n))
            if tstamp:
                expires = _unpk_float(tstamp)
                data["Expires"] = expires
            else:
                expires = None
        return Cookie(k.decode(), v.decode(), data, host)


class CookieDomain:
    "Class for domain that stores cookies"

    def __init__(self, content, jar):
        self.content = content
        bio = io.BytesIO(content)
        nl = _int16unpk(bio.read(2))
        self.jar = jar
        self.name = bio.read(nl).decode()
        self.cookies = []
        for co in bio.read().split(b"\xfe"):
            if co:
                self.cookies.append(Cookie.from_binary(co, self.name))

    def as_binary(self):
        """Returns binary representation for domain"""
        self.check_expired()
        return _binappendstr(self.name) + b"\xfe".join(
            [cook.to_binary() for cook in self.cookies]
        )

    def __delitem__(self, key):
        for ix, i in enumerate(self.cookies):
            if i.name == key:
                del self.cookies[ix]

    def delete_cookie(self, key):
        """Deletes cookie from domain"""

        del self[key]
        self.jar.update()

    def add_cookie(self, header):
        """Adds cookie from header to domain"""
        ck = Cookie.from_header(header, self.name)
        self.delete_cookie(ck.name)
        self.cookies.append(ck)
        self.check_expired()
        self.jar.update()

    def check_expired(self):
        """Checks for expired cookies and deletes them"""
        new_cookies = []
        for c in self.cookies:
            if not c.expired:
                new_cookies.append(c)
            else:
                del c
        self.cookies = new_cookies

    def __getitem__(self, name):
        for cookie in self.cookies:
            if cookie.name == name:
                return cookie

    def __repr__(self):
        return f"<CookieDomain {self.name!r}>"


class CookieJar:
    """Class for cookie jars"""

    def __init__(self, jarfile=HTTPY_DIR / "default" / "cj"):
        try:
            self.jarfile = open(jarfile, "rb")
            self.domains = []
            for dom in self.jarfile.read().split(b"\xff"):
                if dom:
                    self.domains.append(CookieDomain(dom, self))
        except FileNotFoundError:
            self.jarfile = open(jarfile, "wb")
            self.jarfile.close()
            self.jarfile = open(jarfile, "rb")

            self.domains = []
        self.jarfile.close()

    def __contains__(self, host):
        for dom in self.domains:
            if host.endswith(dom.name):
                return True
        return False

    def __getitem__(self, item):
        doms = []
        for dom in self.domains:
            if item.endswith(dom.name):
                doms.append(dom)
        return doms

    def add_domain(self, name):
        """Adds domain to jar"""
        self.domains.append(CookieDomain(_binappendstr(name), self))

    def update(self):
        """Updates jar file with domains"""
        with open(self.jarfile.name, "wb") as f:
            f.write(b"\xff".join(dom.as_binary() for dom in self.domains))
            f.close()

    def get_cookies(self, host, scheme, path):
        """Gets cookies for request"""
        if host not in self:
            return []
        data = []
        for domain in self[host]:
            for cookie in domain.cookies:
                if not (cookie.secure and scheme == "http"):
                    if reslash(path).startswith(reslash(cookie.path)):
                        data.append(cookie)

        return data


class Request:
    def __init__(self, url, headers, method, socket, cache, http_version):
        self.url = url
        self.headers = headers
        self.socket = socket
        self.cache = cache
        self.method = method
        self.http_version = http_version

    def perform(self, enable_cache=False):
        return request(
            self.url,
            enable_cache=enable_cache,
            headers=self.headers,
            method=self.method,
            http_version=self.http_version,
        )

    async def async_perform(self):
        return await async_request(
            self.url, headers=self.headers, method=self.method
        )  # omit http version setting as we can't send async request on http<2


def _threaded_rr(q, url, **kwargs):
    resp = request(url, **kwargs)
    q.put(resp)


class PendingRequest:
    def __init__(self, url, **kwargs):
        if not kwargs.get("blocking", True):
            del kwargs["blocking"]
        self.queue = queue.Queue()
        self.__data_loaded = None
        self.thread = threading.Thread(
            target=(lambda: _threaded_rr(self.queue, url, **kwargs))
        )
        self.thread.start()

    @property
    def empty(self):
        return self.queue.empty()

    def wait(self):
        while not self.finished:
            pass

    @property
    def finished(self):
        return (not self.empty) or (self.__data_loaded is not None)

    @property
    def response(self):
        if self.__data_loaded is not None:
            return self.__data_loaded
        if self.queue.empty():
            return None
        self.__data_loaded = self.queue.get_nowait()
        return self.__data_loaded


class WWW_Authenticate:
    """Class for parsing WWW-Authenticate headers"""

    def __init__(self, header):
        self.header = header
        debugger.info("parsing headers")
        self.scheme, self.raw_params = header.split(" ", 1)
        dbls = self.raw_params.split("=")
        real = []
        o = []
        for i in dbls:
            c = i.rsplit(",", 1)
            if len(c) == 1:
                o.append(i.strip().replace('"', ""))
                if len(o) == 2:
                    real.append(o)
            else:
                if len(o) == 1:
                    o.append(c[0].strip().replace('"', ""))
                    real.append(o)
                    o = [c[1].strip()]
                else:
                    o.append(c[1].strip().replace('"', ""))

    def encode_password(
        self, user, password, path="/", method="GET", original=b"", decoded=b""
    ):
        if self.scheme == "Basic":
            return self.basic_auth(user, password)
        if self.scheme == "Digest":
            return self.digest_auth(user, password, path, method, original)
        raise AuthError(f"unknown authentication scheme : {self.scheme}")

    def digest_auth(self, user, password, path, method, original):
        debugger.info("digest auth")
        alg_name = self.params.get(
            "algorithm", "md5"
        ).lower()  # .lower() is important here!
        debugger.info(f"algorithm is {alg_name}")
        alg_t = alg_name.split("-")
        if len(alg_t) == 1:
            sess = ""
            alg_name = alg_t[0]
        else:
            sess = alg_t[1]
            alg_name = alg_t[0]
        sess = sess == "sess"

        if alg_name not in ALGORITHMS:
            raise DigestAuthError(f"Unknown algorithm :{alg_name!r}")
        alg = ALGORITHMS[alg_name]
        realm = self.params.get("realm", None)
        if realm is None:
            raise DigestAuthError("no realm specified")
        debugger.info(f"realm is {realm}")
        nonce = self.params.get("nonce", None)
        if nonce is None:
            raise DigestAuthError("no nonce specified")
        debugger.info(f"nonce is {nonce}")
        opaque = self.params.get("opaque", None)
        if opaque is None:
            raise DigestAuthError("no opaque specified")
        debugger.info(f"opaque is {opaque}")

        nc = nonce_counter[nonce]
        debugger.info(f"nc is {nc}")
        cnonce = generate_cnonce()
        debugger.info(f"cnonce is {cnonce}")
        qop = self.params.get("qop", None)

        if qop is not None:
            qop = [i.replace(" ", "") for i in qop.split(",")][0]
        debugger.info(f"qop is {qop}")
        debugger.ok("All necessary information got")
        debugger.info(f"creating HA1")
        ha1_data = f"{user}:{realm}:{password}"
        if sess:
            ha1_data = f"{alg(h1_data)}:{nonce}:{cnonce}"
        debugger.info(f"HA1 data  is {ha1_data}")
        debugger.info(f"Hashing HA1 data using {alg_name}")
        ha1 = alg(ha1_data)
        debugger.ok(f"HA1 is {ha1}")
        debugger.info(f"Creating HA2")
        ha2_data = f"{method}:{path}"
        if qop == "auth-int":
            ha2_data = f"{ha2_data}:{alg(original)}"
        debugger.info(f"HA2 data is {ha2_data}")
        debugger.info(f"Hashing HA2 data using {alg_name}")

        ha2 = alg(ha2_data)
        debugger.ok(f"HA2 is {ha2}")
        debugger.info("Building response")
        if qop is None:
            debugger.info("No qop ")
            response_data = f"{ha1}:{cnonce}:{ha2}"
        else:
            response_data = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
        debugger.info(f"Response data is {response_data}")
        debugger.info(f"Hashing response data using {alg_name}")
        response = alg(response_data)
        debugger.ok(f"Response built, response is {response}")
        debugger.info("Building headers")
        auth_headers = f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{path}", '
        if qop is not None:
            auth_headers = f'{auth_headers}qop="{qop}", '
        auth_headers = f'{auth_headers}nc={nc}, cnonce="{cnonce}", response="{response}", opaque="{opaque}"'
        debugger.ok("Headers built")
        return auth_headers

    def basic_auth(self, user, password):
        debugger.info("basic auth")
        string = force_bytes(user) + b":" + force_bytes(password)
        return b"Basic " + base64.b64encode(string)


class NonceCounter:
    """nonce use counter, used to get nc parameter in digest auth"""

    def __init__(self):
        self.nonces = {}

    def __getitem__(self, item):
        if item not in self.nonces:
            debugger.info("Adding new nonce to nonce_counter")
            self.nonces[item] = 0
        debugger.info("Incrementing nonce_counter")
        self.nonces[item] += 1
        return format(self.nonces[item], "08x")


class PickleFile(dict):
    def __init__(self, fn):
        self.fn = fn
        if not os.path.exists(fn):
            with open(fn, "wb") as f:
                pickle.dump({}, f)
        with open(fn, "rb") as f:
            self._dict = pickle.load(f)
        super().__init__(self._dict)

    def update(self):
        with open(self.fn, "rb") as f:
            self._dict = pickle.load(f)
        super().__init__(self._dict)

    def __getitem__(self, item):
        self.update()
        return self._dict[item]

    def __setitem__(self, item, value):
        self._dict[item] = value
        with open(self.fn, "wb") as f:
            pickle.dump(self._dict, f)

    def __delitem__(self, item):
        del self._dict[item]
        with open(self.fn, "wb") as f:
            pickle.dump(self._dict, f)

    def __contains__(self, item):
        return item in self._dict


class Connection:
    """Class for connnections"""

    def __init__(self, sock, timeout=math.inf, max=math.inf, is_http2=False):
        debugger.info(f"Created new Connection upon {sock}")
        self._sock = sock
        self.timeout = timeout
        self.max = max
        self.is_http2 = is_http2
        self.requests = 0
        self.time_started = time.time()
        self.is_async = isinstance(self.sock, http2.connection.AsyncConnection)

    @property
    def sock(self):
        if self.is_http2:
            return self._sock
        self.requests += 1
        if self.time_started + self.timeout < time.time():
            debugger.warn(f"Connection expired")
            raise ConnectionExpiredError("Connection expired")
        if self.requests > self.max:
            debugger.warn(f"Connection limit reached")
            raise ConnectionLimitError("connection limit reached")
        return self._sock

    def close(self):
        cl = self._sock.close()
        if asyncio.iscoroutine(cl):
            try:
                asyncio.new_event_loop().run_until_complete(cl)
            except RuntimeError:
                pass


class Session:
    """Class for connection sessions"""

    def __init__(self):
        sessions.append(self)
        self.connections = {}
        atexit.register(self.close)

    def __setitem__(self, host, connection):
        host, port = host
        if is_closed(connection):
            raise ConnectionClosedError("Connection closed by host")
        self.connections[host, port, connection.is_async] = connection

    def __getitem__(self, host):
        try:
            sock = self.connections[host].sock
        except ConnectionError:  # maybe handle? TODO in 2.1
            raise
        if is_closed(self.connections[host]):
            del self.connections[host]
            raise ConnectionClosedError("Connection closed by host")
        return sock, self.connections[host].is_http2

    async def initiate_http2_connection(self, *args, **kwargs):
        kwargs["session"] = self
        await initiate_http2_connection(*args, **kwargs)

    def request(self, *args, **kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "connection" not in kwargs["headers"]:
            kwargs["headers"]["connection"] = "Keep-Alive"
        kwargs["session"] = self
        return request(*args, **kwargs)

    async def async_request(self, *args, **kwargs):
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        if "connection" not in kwargs["headers"]:
            kwargs["headers"]["connection"] = "Keep-Alive"
        kwargs["session"] = self
        return await async_request(*args, **kwargs)

    def __contains__(self, host):
        return host in self.connections

    def __delitem__(self, host):
        if host not in self:
            return
        del self.connections[host]

    def close(self):
        for conn in self.connections.values():
            conn.close()

    def __del__(self):
        self.close()


class KeepAlive:
    """Class for parsing keep-alive headers"""

    def __init__(self, header):
        self.params = CaseInsensitiveDict({})
        if header:
            params = header.split(",")
            self.params = CaseInsensitiveDict(j.strip().split("=") for j in params)
        self.timeout = float(self.params.get("timeout", math.inf))
        self.max = float(self.params.get("max", math.inf))


def hashing_function(function_name):
    hashlib_function = getattr(hashlib, function_name)

    @functools.wraps(function_name)
    def decorated(to_hash):
        to_hash = force_bytes(to_hash)
        return hashlib_function(to_hash).hexdigest()

    decorated.__qualname__ = function_name
    return decorated


md5, sha256, sha512, sha1 = (
    hashing_function(i) for i in ("md5", "sha256", "sha512", "sha1")
)
ALGORITHMS = {"md5": md5, "sha256": sha256, "sha512": sha512, "sha1": sha1}


def create_socket(host, port, cert, verify, check_hostname, alpn_protocols, https):
    conn = _create_connection_and_handle_errors((host, port))
    if https:
        context = generate_ssl_context(
            check_hostname=check_hostname,
            verify=verify,
            cert=cert,
            alpn_protocols=alpn_protocols,
        )
        protocol, conn = alpn_negotiate(conn, context, host)
    else:
        protocol = "http/1.1"
    return protocol, conn


def create_connection(
    host,
    port,
    last_response,
    http_version,
    scheme,
    do_keep_alive,
    session,
    cert,
    verify,
    check_hostname,
):
    """
    Creates a connection to a given host and port
    """
    debugger.info("calling socket.create_connection")
    if http_version is not None and http_version not in ALPN_PROTOCOLS:
        raise LookupError(f"Unknown HTTP version: {http_version!r}")
    protocol, conn = create_socket(
        host,
        port,
        cert,
        verify,
        check_hostname,
        ALPN_PROTOCOLS[http_version or "*"],
        scheme == "https",
    )
    http_version = {"http/1.1": "1.1", "h2": "2"}.get(protocol, None)
    if http_version is None:
        raise HTTPyError(
            f"server doesn't support http: unknown alpn result: {protocol!r}"
        )

    debugger.info(f"http version: {http_version}")
    is_http2 = http_version == "2"
    is_async = False
    keep_alive = KeepAlive(last_response.headers.get("Keep-Alive", ""))
    if (host, port, is_async) in session and do_keep_alive:
        if session[host, port, is_async][1] == is_http2:
            debugger.info("Connection already in session")
            try:
                return session[host, port, is_async][0], True, http_version
            except ConnectionClosedError:
                debugger.warn("Connection already expired.")
    if is_http2:
        if conn.selected_alpn_protocol() != "h2":
            raise ConnectionError("failed to connect: server does not support http2")

        debugger.info("instancing http2 connection")
        conn = http2.Connection.from_socket(conn, debugger, host, port)
        conn.start()
    if do_keep_alive:
        debugger.info("adding to session")
        session[host, port] = Connection(
            conn, keep_alive.timeout, keep_alive.max, is_http2
        )
    return conn, False, http_version


async def create_async_h2_connection(
    host, port, last_response, http_version, scheme, session
):
    is_http2 = http_version == "2"
    if not is_http2:
        raise ValueError(
            "can't create an async connection with http/1.1 (use aiohttp for this)"
        )
    keep_alive = KeepAlive(last_response.headers.get("Keep-Alive", ""))
    if (host, port, True) in session:
        if session[host, port, True][1] == is_http2:
            debugger.info("Connection already in session")
            try:
                return session[host, port, True][0], True, http_version
            except ConnectionClosedError:
                debugger.warn("Connection already expired.")
    debugger.info("instancing http2 connection")
    conn = http2.connection.AsyncConnection(host, port, debugger)
    await conn.start()
    session[host, port] = Connection(conn, keep_alive.timeout, keep_alive.max, is_http2)
    return conn, False, http_version


def generate_dir_id():
    return "".join(random.choices(string.hexdigits, k=16))


def setup_dir(dir_path, name):
    os.makedirs(dir_path / "sites", exist_ok=True)
    if not os.path.exists(dir_path / "permredir.pickle"):
        with open(dir_path / "permredir.pickle", "wb") as f:
            pickle.dump({}, f)
    if not os.path.exists(dir_path / "cj"):
        with open(dir_path / "cj", "wb") as f:
            f.write(b"")

    if not os.path.exists(dir_path / "meta.json"):
        if name is None:
            name = f"session-{dir_count()+1}"
        with open(dir_path / "meta.json", "w") as f:
            json.dump({"name": name}, f)
    elif name is not None:
        # don't reset additional meta
        with open(dir_path / "meta.json", "w") as f:
            json.dump({"name": name}, f)
    else:
        with open(dir_path / "meta.json", "r") as f:
            meta = json.load(f)
            name = meta["name"]
    return name


def find_dir_by_id(sessid, name):
    if sessid in os.listdir(HTTPY_DIR / "dirs"):
        return HTTPY_DIR / "dirs" / sessid
    else:
        for q in os.listdir(HTTPY_DIR / "dirs"):
            try:
                with open(os.path.join(HTTPY_DIR, "dirs", q, "meta.json")) as f:
                    if json.load(f)["name"] == name:
                        return HTTPY_DIR / "dirs" / q
            except (FileNotFoundError, KeyError):
                raise


def dir_count():
    return len(os.listdir(HTTPY_DIR / "dirs"))


class Dir:
    def __init__(self, path=None, dir_id=None, name=None):
        if dir_id is None:
            dir_id = generate_dir_id()

        if path is None:
            path = find_dir_by_id(dir_id, name)
            dir_id = os.path.split(path)[-1]
            if path is None:
                path = HTTPY_DIR / "dirs" / dir_id
        path = pathlib.Path(path)
        self.new = not os.path.exists(path)
        name = setup_dir(path, name)
        self.name = name
        self.dir_id = dir_id
        self.path = path
        self.jar = CookieJar(path / "cj")
        self.permanent_redirects = PickleFile(path / "permredir.pickle")
        self.cache = Cache(path / "sites")
        if self.new:
            dirs.append(self)

    def request(self, url, **kwargs):
        if "base_dir" in kwargs:
            del kwargs["base_dir"]
        kwargs["enable_cache"] = kwargs.get("enable_cache", True)
        kwargs["enable_cookies"] = kwargs.get("enable_cookies", True)
        return request(url, **kwargs, base_dir=self.path)

    def __repr__(self):
        return f"<Dir {self.name} ( {self.dir_id} ) at {self.path!r}>"


def _dictrm(d, l):
    for i in l:
        if i.lower() in d:  # caseInsensitiveDict
            debugger.info(f"dictrming {i}")
            del d[i.lower()]
        elif i in d:
            debugger.info(f"dictrming {i}")
            del d[i]
        else:
            debugger.warn(f"dictrm {i} failed: not in dict")


proto_versions = {"1.1": HTTP11(), "2": HTTP2()}
nonce_counter = NonceCounter()
sessions = []
default_session = Session()
dir_ids = os.listdir(HTTPY_DIR / "dirs")
dirs = []
dirs = [Dir(dir_id=i) for i in dir_ids]
default_dir = Dir(path=HTTPY_DIR / "default", name="default")
permanent_redirects = PickleFile(HTTPY_DIR / "default" / "permredir.pickle")


async def _async_raw_request(
    host,
    port,
    path,
    scheme,
    session=default_session,
    url="",
    method="GET",
    data=b"",
    content_type=None,
    timeout=32,
    enable_cache=False,
    headers={},
    auth={},
    history=[],
    debug=False,
    last_status=-1,
    pure_headers=False,
    base_dir=HTTPY_DIR / "default",
    http_version="2",
    disabled_headers=[],
    force_keep_alive=False,
    enable_cookies=False,
    stream=False,
    check_hostname=True,
    verify=None,
    cert=None,
):
    base_dir = pathlib.Path(base_dir)
    method = method.upper()
    if enable_cache:
        cache = Cache(base_dir / "sites")
    if enable_cookies:
        jar = CookieJar(base_dir / "cj")

    permanent_redirects = PickleFile(base_dir / "permredir.pickle")
    headers = {capitalize(key): value for key, value in headers.items()}
    debug = debug or getattr(builtins, "debug", False)
    debugger = _Debugger(debug)
    debugger.info("_async_raw_request() called.")
    if (host, port, path) in permanent_redirects:
        nep = permanent_redirects[host, port, path]
        debugger.info(f"Permanently redirecting from {path} to {nep}")
        return Response(
            method,
            Status(b"301 Moved Permanently"),
            {"Location": nep},
            "",
            history,
            url,
            True,
            b"",
            0,
        )

    if method not in HTTPY_CACHEABLE_METHODS:
        enable_cache = False
    if enable_cache:
        debugger.info("Accessing cache.")
        cf = cache[deslash(url), method]
        if cf and not cf.expired:
            debugger.info("Not expired data in cache, loading from cache")
            return Response.cacheload(cf, Request)
        else:
            debugger.info("No data in cache.")
    else:
        debugger.info("Cache disabled.")
        cf = None
    defhdr = CaseInsensitiveDict(
        {
            "Accept-Encoding": "gzip, deflate, identity",
            "Host": makehost(host, port),
            "User-Agent": "httpy/" + VERSION,
            "Connection": "close",
            "Accept": "*/*",
        }
    )
    if stream:
        defhdr["Accept-Encoding"] = "identity"  # bugfx
    if data:
        debugger.info("Adding form data")
        data, cth = encode_form_data(data, content_type)
        defhdr.update(cth)
    if auth and last_status == 401:
        debugger.info("adding authentication")
        last_response = history[-1]
        if "www-authenticate" not in last_response.headers:
            raise AuthError(
                "Server responded with 401 Unauthorized without WWW-Authenticate header."
            )
        wau = WWW_Authenticate(last_response.headers["www-authenticate"])

        defhdr["Authorization"] = wau.encode_password(
            *auth, path, method, last_response._original, last_response.content
        )
    if enable_cookies:
        cookies = jar.get_cookies(makehost(host, port), scheme, path)
        if cookies:
            defhdr["Cookie"] = []
            for c in cookies:
                defhdr["Cookie"].append(c.name + "=" + c.value)

    defhdr.update(headers)
    debugger.info("Removing disabled headers")
    _dictrm(defhdr, disabled_headers)
    debugger.info("Establishing connection ")
    if history:
        last_response = history[-1]
    else:
        last_response = Response.plain()
    sock, from_session, http_version = await create_async_h2_connection(
        host, port, last_response, http_version, scheme, session
    )
    start_time = time.time()

    try:
        defhdr.update(headers)
        if pure_headers:
            defhdr = headers
        if cf:
            cf.add_header(defhdr)
        proto = _HTTP2Async()
        try:
            ret_val = await proto.send_request(
                sock, method, defhdr, data, path, debugger
            )
        except BrokenPipeError:
            headers["connection"] = "close"
            return await _async_raw_request(
                host,
                port,
                path,
                scheme,
                session=session,
                url=url,
                method=method,
                data=data,
                content_type=content_type,
                timeout=timeout,
                enable_cache=enable_cache,
                headers=headers,
                auth=auth,
                history=history,
                debug=debug,
                last_status=last_status,
                pure_headers=pure_headers,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                force_keep_alive=force_keep_alive,
                enable_cookies=enable_cookies,
                stream=stream,
            )

        args = (sock, ret_val)
        if stream:
            q = await proto.stream_response(*args)
            await q.load_state()
            return q
        status, resp_headers, decoded_body, body = await proto.recv_response(*args)

        if status == 304:
            return Response.cacheload(cf, Request)
        if "set-cookie" in resp_headers and enable_cookies:
            cookies = resp_headers["set-cookie"]
            h = makehost(host, port)
            if h not in jar:
                jar.add_domain(h)
            domain = jar[h][0]
            if isinstance(cookies, list) or isinstance(cookies, tuple):
                for c in cookies:
                    domain.add_cookie(c)
            else:
                domain.add_cookie(cookies)
    except DeadConnectionError:
        debugger.error("Connection closed")
        del session[host, port]
        if not force_keep_alive:
            headers["connection"] = "close"
            debugger.info("Keep-Alive not forced, retrying")
            return await _async_raw_request(
                host,
                port,
                path,
                scheme,
                session=session,
                url=url,
                method=method,
                data=data,
                content_type=content_type,
                timeout=timeout,
                enable_cache=enable_cache,
                headers=headers,
                auth=auth,
                history=history,
                debug=debug,
                last_status=last_status,
                pure_headers=pure_headers,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                force_keep_alive=force_keep_alive,
            )
        raise
    except:
        del session[host, port]
        raise

    if headers.get("connection") == "keep-alive":
        session.connections[host, port]._sock = (
            sock  # Fix bug #23 -- New  connections in keep-alive mode slowing down requests
        )
    end_time = time.time()
    elapsed_time = end_time - start_time

    return Response(
        method,
        status,
        resp_headers,
        decoded_body,
        history,
        url,
        False,
        body,
        Request(url, defhdr, method, sock, False, http_version),
        elapsed_time,
        enable_cache,
        base_dir,
    )


def _raw_request(
    host,
    port,
    path,
    scheme,
    session=default_session,
    url="",
    method="GET",
    data=b"",
    content_type=None,
    timeout=32,
    enable_cache=False,
    headers={},
    auth={},
    history=[],
    debug=False,
    last_status=-1,
    pure_headers=False,
    base_dir=HTTPY_DIR / "default",
    http_version=None,
    disabled_headers=[],
    force_keep_alive=False,
    enable_cookies=False,
    stream=False,
    cert=None,
    verify=True,
    check_hostname=True,
):
    base_dir = pathlib.Path(base_dir)
    method = method.upper()
    if enable_cache:
        cache = Cache(base_dir / "sites")
    if enable_cookies:
        jar = CookieJar(base_dir / "cj")
    permanent_redirects = PickleFile(base_dir / "permredir.pickle")
    headers = {capitalize(key): value for key, value in headers.items()}
    debug = debug or getattr(builtins, "debug", False)
    debugger.info("_raw_request() called.")
    if (host, port, path) in permanent_redirects:
        nep = permanent_redirects[host, port, path]
        debugger.info(f"Permanently redirecting from {path} to {nep}")
        return Response(
            method,
            Status(b"301 Moved Permanently"),
            {"Location": nep},
            "",
            history,  #
            url,
            True,
            b"",
            0,
        )

    socket.setdefaulttimeout(timeout)
    if method not in HTTPY_CACHEABLE_METHODS:
        enable_cache  # = False
    if enable_cache:
        debugger.info("Accessing cache.")
        cf = cache[deslash(url), method]
        if cf and not cf.expired:
            debugger.info("Not expired data in cache, loading from cache")
            return Response.cacheload(cf, Request)
        else:
            debugger.info("No data in cache.")
    else:
        debugger.info("Cache disabled.")
        cf = None

    ### TODO BUILD_HEADERS FUNCTION TO MAKE THE CODE DRIER
    defhdr = CaseInsensitiveDict(
        {
            "Accept-Encoding": "gzip, deflate, identity",
            "Host": makehost(host, port),
            "User-Agent": "httpy/" + VERSION,
            "Connection": "close",
            "Accept": "*/*",
        }
    )
    if stream:
        defhdr["Accept-Encoding"] = "identity"
    if data:
        debugger.info("Adding form data")
        data, cth = encode_form_data(data, content_type)
        defhdr.update(cth)
    if auth and last_status == 401:
        debugger.info("adding authentication")
        last_response = history[-1]
        if "www-authenticate" not in last_response.headers:
            raise AuthError(
                "Server responded with 401 Unauthorized without WWW-Authenticate header."
            )
        wau = WWW_Authenticate(last_response.headers["www-authenticate"])

        defhdr["Authorization"] = wau.encode_password(
            *auth, path, method, last_response._original, last_response.content
        )
    if enable_cookies:
        cookies = jar.get_cookies(makehost(host, port), scheme, path)
        if cookies:
            defhdr["Cookie"] = []
            for c in cookies:
                defhdr["Cookie"].append(c.name + "=" + c.value)
    defhdr.update(headers)
    debugger.info("Removing disabled headers")
    _dictrm(defhdr, disabled_headers)
    debugger.info("Establishing connection ")
    if history:
        last_response = history[-1]
    else:
        last_response = Response.plain()
    sock, from_session, http_version = create_connection(
        host,
        port,
        last_response,
        http_version,
        scheme,
        defhdr.get("connection") == "keep-alive",
        session,
        cert,
        verify,
        check_hostname,
    )
    is_http2 = http_version == "2"
    start_time = time.time()

    try:
        if pure_headers:
            defhdr = headers
        if cf:
            cf.add_header(defhdr)
        proto = proto_versions[http_version]
        dbg = debugger if is_http2 else debug
        try:
            ret_val = proto.send_request(sock, method, defhdr, data, path, dbg)
        except BrokenPipeError:
            debugger.warn("broken pipe, reconnecting")
            headers["connection"] = "close"
            return _raw_request(
                host,
                port,
                path,
                scheme,
                session=session,
                url=url,
                method=method,
                data=data,
                content_type=content_type,
                timeout=timeout,
                enable_cache=enable_cache,
                headers=headers,
                auth=auth,
                history=history,
                debug=debug,
                last_status=last_status,
                pure_headers=pure_headers,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                force_keep_alive=force_keep_alive,
                stream=stream,
                check_hostname=check_hostname,
                cert=cert,
                verify=verify,
            )

        if is_http2:
            args = (sock, ret_val)
        else:
            args = (sock, dbg, timeout)
        if stream:
            stream_obj = proto.stream_response(*args)
            if not isinstance(stream_obj, tuple):
                return stream_obj
            status, resp_headers, decoded_body, body = stream_obj
        else:
            status, resp_headers, decoded_body, body = proto.recv_response(*args)

        if status == 304:
            return Response.cacheload(cf, Request)
        if "set-cookie" in resp_headers and enable_cookies:
            cookies = resp_headers["set-cookie"]
            h = makehost(host, port)
            if h not in jar:
                jar.add_domain(h)
            domain = jar[h][0]
            if isinstance(cookies, list) or isinstance(cookies, tuple):
                for c in cookies:
                    domain.add_cookie(c)
            else:
                domain.add_cookie(cookies)
    except DeadConnectionError:
        debugger.error("Connection closed")
        del session[host, port]
        if not force_keep_alive:
            debugger.info("Keep-Alive not forced, retrying")
            headers["connection"] = "close"
            return _raw_request(
                host,
                port,
                path,
                scheme,
                session=session,
                url=url,
                method=method,
                data=data,
                content_type=content_type,
                timeout=timeout,
                enable_cache=enable_cache,
                headers=headers,
                auth=auth,
                history=history,
                debug=debug,
                last_status=last_status,
                pure_headers=pure_headers,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                force_keep_alive=force_keep_alive,
                stream=stream,
                check_hostname=check_hostname,
                verify=verify,
                cert=cert,
            )
        raise
    except:
        del session[host, port]
        raise

    if headers.get("connection") == "keep-alive":
        session.connections[host, port]._sock = (
            sock  # Fix bug #23 -- New  connections in keep-alive mode slowing down requests
        )
    end_time = time.time()
    elapsed_time = end_time - start_time

    return Response(
        method,
        status,
        resp_headers,
        decoded_body,
        history,
        url,
        False,
        body,
        Request(url, defhdr, method, sock, False, http_version),
        elapsed_time,
        enable_cache,
        base_dir,
    )


def set_debug(d=True):
    builtins.debug = d


def absolute_path(url, last_url, scheme, host):
    """Makes relative urls absolute"""
    if URLPATTERN.search(url) is not None:
        debugger.info("Absolute url")
        return url
    if url.startswith("/"):
        debugger.info("Site root redirect")
        res = f"{scheme}://{host}{url}"
    else:
        debugger.info(f"Relative redirect to {url}")

        res = f"{scheme}://{reslash(last_url)}{url}"
    debugger.info(f"Redirecting to {res}")
    return res


def request(
    url,
    *,
    session=default_session,
    method="GET",
    headers={},
    body=b"",
    auth=(),
    redirlimit=20,
    content_type=None,
    timeout=30,
    history=None,
    throw_on_error=False,
    debug=False,
    pure_headers=False,
    enable_cache=False,
    base_dir=HTTPY_DIR / "default",
    http_version=None,
    disabled_headers=[],
    blocking=True,
    force_keep_alive=False,
    enable_cookies=False,
    stream=False,
    cert=None,
    verify=None,
    check_hostname=True,
):
    """

    Performs request.

    `Note:` all arguments but ``url`` are keyword-only

    :param url: url to request
    :type url: ``str``
    :param method: method to use, defaults to ``"GET"``
    :type method: ``str``
    :param headers: headers to add to the request, defaults to ``{}``
    :type headers: ``dict``
    :param body: request body, can be ``bytes`` , ``str`` or  ``dict``, defaults to ``b''``
    :param auth: credentials to use (``{"username":"password"}``), defaults to ``{}``
    :type auth: ``tuple``
    :param redirlimit: redirect limit . If number of redirects has reached ``redirlimit``, ``TooManyRedirectsError`` will be raised. Defaults to ``20``.
    :type redirlimit: ``int``
    :param content_type: content type of request body, defaults to ``None``
    :param timeout: request timeout, defaults to ``30``
    :type timeout: ``int``
    :param history: request history, defaults to ``None``
    :param throw_on_error: if throw_on_error is ``True`` , StatusError will be raised if server responded with 4xx or 5xx status code.
    :param debug: whether or not shall debug mode be used , defaults to ``False``
    :type debug: ``bool``
    :param base_dir: HTTPy cache directory to use for the request, default is ``"~/.cache/httpy/default"``
    :type base_dir: ``pathlib.Path``
    :param http_version: HTTP version to use, MUST be "1.1" or "2" or None. If None the HTTP version will be automatically detected via ALPN.
    :param disabled_headers: Disable selected headers.
    :type disabled_headers: ``list``
    :param blocking: If ``False``, request is performed in a separate thread. Defaults to ``True``
    :type blocking: ``bool``
    :param force_keep_alive: If ``False``, request will be retried upon connection being closed if the connection is in keep-alive mode.
    :type force_keep_alive:``bool``

    """
    global debugger
    debugger = _Debugger(debug)
    builtins.debugger = _Debugger(debug)
    debugger.info("request() called.")
    debugger.info(f"Requesting {url}")
    history = [] if history is None else history
    debugger.info(f"Parsing url")
    result = URLPATTERN.search(url)
    if result is None:
        debugger.warn(f"Invalid url {url} ")
        raise ValueError("Invalid URL")
    groups = result.groupdict()
    if "path" not in groups:
        groups["path"] = "/"
    scheme = groups["scheme"]
    path = groups["path"]
    host = groups["host"]

    if scheme not in schemes:
        raise ValueError("Invalid scheme")
    if "port" in groups:
        port = groups["port"]
    else:
        port = schemes[scheme]
    if port is None:
        port = schemes[scheme]

    if http_version == "2" and scheme == "http":
        raise HTTPyError("can't perform a HTTP/2 request over an insecure connection")
    if history:
        last_status = history[-1].status
    else:
        last_status = -1
    debugger.info(f"Sending request to {host} port {port} via {scheme}")
    if blocking:  # normal raw request
        resp = _raw_request(
            host,
            port,
            "/" + path,
            scheme,
            session=session,
            url=url,
            history=history,
            auth=auth,
            data=body,
            method=method,
            headers=headers,
            timeout=timeout,
            content_type=content_type,
            debug=debug,
            last_status=last_status,
            pure_headers=pure_headers,
            enable_cache=enable_cache,
            base_dir=base_dir,
            http_version=http_version,
            disabled_headers=disabled_headers,
            force_keep_alive=force_keep_alive,
            enable_cookies=enable_cookies,
            stream=stream,
            cert=cert,
            verify=verify,
            check_hostname=check_hostname,
        )
    else:  # PendingRequest
        return PendingRequest(
            url,
            session=session,
            auth=auth,
            redirlimit=redirlimit,
            timeout=timeout,
            body=body,
            headers=headers,
            content_type=content_type,
            history=history,
            debug=debug,
            pure_headers=pure_headers,
            enable_cache=enable_cache,
            base_dir=base_dir,
            http_version=http_version,
            blocking=False,
            force_keep_alive=force_keep_alive,
            enable_cookies=enable_cookies,
            cert=cert,
            verify=verify,
            check_hostname=check_hostname,
        )

    if 300 <= resp.status < 400:
        debugger.info("Redirect")
        if resp.status == 301:
            debugger.info("Updating permanent redirects data file")
            permanent_redirects[host, port, "/" + path] = resp.headers["Location"]

        if len(history) >= redirlimit:
            debugger.warn("too many redirects!")
            raise TooManyRedirectsError("too many redirects")
        if "Location" in resp.headers:
            return request(
                absolute_path(
                    resp.headers["Location"], url, scheme, makehost(host, port)
                ),
                session=session,
                auth=auth,
                redirlimit=redirlimit,
                timeout=timeout,
                body=body,
                headers=headers,
                content_type=content_type,
                history=resp.history,
                debug=debug,
                pure_headers=pure_headers,
                enable_cache=enable_cache,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                blocking=blocking,
                enable_cookies=enable_cookies,
                stream=stream,
            )
    if resp.status == 401 and auth:
        if last_status == 401:
            debugger.warn("Invalid credentials!")
            return resp
        return request(
            url,
            session=session,
            auth=auth,
            redirlimit=redirlimit,
            timeout=timeout,
            body=body,
            headers=headers,
            content_type=content_type,
            history=resp.history,
            debug=debug,
            pure_headers=pure_headers,
            enable_cache=enable_cache,
            base_dir=base_dir,
            http_version=http_version,
            blocking=blocking,
            enable_cookies=enable_cookies,
            stream=stream,
        )
    if 399 < resp.status < 500:
        debugger.warn(f"Client error : {resp.status} {resp.reason}")
        if throw_on_error:
            raise ClientError(
                f"\n{resp.status} {resp.reason}: {resp.status.description}"
            )
    if 499 < resp.status < 600:
        if throw_on_error:
            raise ServerError(
                f"\n{resp.status} {resp.reason}: {resp.status.description}"
            )
        debugger.warn(f"Server error : {resp.status} {resp.reason}")
    if resp.ok:
        debugger.ok(f"Response OK")
    return resp


async def async_request(
    url,
    *,
    session=default_session,
    method="GET",
    headers={},
    body=b"",
    auth=(),
    redirlimit=20,
    content_type=None,
    timeout=30,
    history=None,
    throw_on_error=False,
    debug=False,
    pure_headers=False,
    enable_cache=False,
    base_dir=HTTPY_DIR / "default",
    http_version="2",
    disabled_headers=[],
    force_keep_alive=False,
    enable_cookies=False,
    stream=False,
):
    """

    Performs an asynchronous request.
    Asynchronous requests are always HTTP/2.

    `Note:` all arguments but ``url`` are keyword-only

    :param url: url to request
    :type url: ``str``
    :param method: method to use, defaults to ``"GET"``
    :type method: ``str``
    :param headers: headers to add to the request, defaults to ``{}``
    :type headers: ``dict``
    :param body: request body, can be ``bytes`` , ``str`` or  ``dict``, defaults to ``b''``
    :param auth: credentials to use (``{"username":"password"}``), defaults to ``{}``
    :type auth: ``tuple``
    :param redirlimit: redirect limit . If number of redirects has reached ``redirlimit``, ``TooManyRedirectsError`` will be raised. Defaults to ``20``.
    :type redirlimit: ``int``
    :param content_type: content type of request body, defaults to ``None``
    :param timeout: request timeout, defaults to ``30``
    :type timeout: ``int``
    :param history: request history, defaults to ``None``
    :param throw_on_error: if throw_on_error is ``True`` , StatusError will be raised if server responded with 4xx or 5xx status code.
    :param debug: whether or not shall debug mode be used , defaults to ``False``
    :type debug: ``bool``
    :param base_dir: HTTPy cache directory to use for the request, default is ``"~/.cache/httpy/default"``
    :type base_dir: ``pathlib.Path``
    :param http_version: HTTP version to use, MUST be "2". For async http/1 requests use aiohttp or the `blocking` parameter of request() for requests in a separate thread
    :param disabled_headers: Disable selected headers.
    :type disabled_headers: ``list``
    :param force_keep_alive: If ``False``, request will be retried upon connection being closed if the connection is in keep-alive mode.
    :type force_keep_alive:``bool``

    """
    global debugger
    debugger = _Debugger(debug)
    builtins.debugger = _Debugger(debug)
    debugger.info("request() called.")
    debugger.info(f"Requesting {url}")
    history = [] if history is None else history
    debugger.info(f"Parsing url")
    result = URLPATTERN.search(url)
    if result is None:
        debugger.warn(f"Invalid url {url} ")
        raise ValueError("Invalid URL")
    groups = result.groupdict()
    if "path" not in groups:
        groups["path"] = "/"
    scheme = groups["scheme"]
    path = groups["path"]
    host = groups["host"]

    if scheme not in schemes:
        raise ValueError("Invalid scheme")
    if "port" in groups:
        port = groups["port"]
    else:
        port = schemes[scheme]
    if port is None:
        port = schemes[scheme]

    if history:
        last_status = history[-1].status
    else:
        last_status = -1
    debugger.info(f"Sending request to {host} port {port} via {scheme}")
    resp = await _async_raw_request(
        host,
        port,
        "/" + path,
        scheme,
        session=session,
        url=url,
        history=history,
        auth=auth,
        data=body,
        method=method,
        headers=headers,
        timeout=timeout,
        content_type=content_type,
        debug=debug,
        last_status=last_status,
        pure_headers=pure_headers,
        enable_cache=enable_cache,
        base_dir=base_dir,
        http_version=http_version,
        disabled_headers=disabled_headers,
        force_keep_alive=force_keep_alive,
        enable_cookies=enable_cookies,
        stream=stream,
    )
    if 300 <= resp.status < 400:
        debugger.info("Redirect")
        if resp.status == 301:
            debugger.info("Updating permanent redirects data file")
            permanent_redirects[host, port, "/" + path] = resp.headers["Location"]

        if len(history) >= redirlimit:
            debugger.warn("too many redirects!")
            raise TooManyRedirectsError("too many redirects")
        if "Location" in resp.headers:
            return await async_request(
                absolute_path(
                    resp.headers["Location"], url, scheme, makehost(host, port)
                ),
                session=session,
                auth=auth,
                redirlimit=redirlimit,
                timeout=timeout,
                body=body,
                headers=headers,
                content_type=content_type,
                history=resp.history,
                debug=debug,
                pure_headers=pure_headers,
                enable_cache=enable_cache,
                base_dir=base_dir,
                http_version=http_version,
                disabled_headers=disabled_headers,
                enable_cookies=enable_cookies,
                stream=stream,
            )
    if resp.status == 401 and auth:
        if last_status == 401:
            debugger.warn("Invalid credentials!")
            return resp
        return await async_request(
            url,
            session=session,
            auth=auth,
            redirlimit=redirlimit,
            timeout=timeout,
            body=body,
            headers=headers,
            content_type=content_type,
            history=resp.history,
            debug=debug,
            pure_headers=pure_headers,
            enable_cache=enable_cache,
            base_dir=base_dir,
            http_version=http_version,
            enable_cookies=enable_cookies,
            stream=stream,
        )
    if 399 < resp.status < 500:
        debugger.warn(f"Client error : {resp.status} {resp.reason}")
        if throw_on_error:
            raise ClientError(
                f"\n{resp.status} {resp.reason}: {resp.status.description}"
            )
    if 499 < resp.status < 600:
        if throw_on_error:
            raise ServerError(
                f"\n{resp.status} {resp.reason}: {resp.status.description}"
            )
        debugger.warn(f"Server error : {resp.status} {resp.reason}")
    if resp.ok:
        debugger.ok(f"Response OK")
    return resp


async def initiate_http2_connection(url=None, host=None, session=default_session):
    """
    Starts a HTTP/2 connection and adds it to a session.
    Used to send multiple asynchronous requests on one connection.
    """
    if url is None and host is None:
        raise ValueError
    if url is not None:
        result = URLPATTERN.search(url)
        if not result:
            raise ValueError("Invalid URL")
        host = result.group("host")
    port = 443
    await create_async_h2_connection(
        host, port, Response.plain(), "2", "https", session
    )


def close_all():
    """
    Closes all sessions.
    Always called at program exit.
    """
    for session in sessions:
        session.close()
    default_session.close()


def get_connection(host, port):
    """
    Returns a connection in the default session.
    """
    conn = default_session[(host, port)]
    return conn


debugger = _Debugger(False)


def generate_websocket_key():
    """Generates a websocket key"""
    return base64.b64encode(
        ("".join(random.choices(string.ascii_letters + string.digits, k=16))).encode()
    )


def websocket_handshake(
    url, key, cdebugger, subprotocol=None, origin=None, additional_headers={}
):
    """
    Performs a WebSocket Handshake

    :param url: url to send request to
    :type url: str
    :param key: WebSocket secret key
    :type key: str
    :param subprotocol: Subprotocol to use, defaults to `None`
    :type subprotocol: str or None
    :param origin: Origin of request, defaults to `None`
    :type origin: str or None
    :param additional_headers: Additional headers to send request with, defaults to `{}`
    :type additional_headers: dict
    """
    cdebugger.info("started handshake")
    base = {
        "Host": get_host(url),
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": key,
    }
    if origin is not None:
        base["origin"] = origin
    if subprotocol is not None:
        base["Sec-WebSocket-Protocol"] = subprotocol
    base.update(additional_headers)
    cdebugger.info("sending request")

    with warnings.catch_warnings():
        set_debug(False)
        warnings.filterwarnings(
            "ignore",
            message="no content-length nor transfer-encoding, setting socket timeout",
        )
        response = request(
            url, headers=base, pure_headers=True, enable_cache=False, http_version="1.1"
        )
    set_debug()
    cdebugger.info("checking response")
    if response.status != 101:
        raise WebSocketHandshakeError(
            f"Invalid status in handshake, expected 101, got {response.status}"
        )
    accept = response.headers["Sec-WebSocket-Accept"]
    encoded = hashlib.sha1(key + WEBSOCKET_GUID).digest()
    check = base64.b64encode(encoded).decode()
    if accept != check:
        raise WebSocketHandshakeError(
            f"Invalid Sec-WebSocket-Accept header field, expected {check} got {accept}"
        )
    cdebugger.ok("Handshake Ok")
    return response


class strarray:
    def __init__(self, data=""):
        self.__b = list(self._ordize(i) for i in data)

    def _ordize(self, d):
        if isinstance(d, str):
            return ord(d)
        elif isinstance(d, int):
            return d
        raise TypeError(f"can't add type {type(d).__name__!r} to strarray")

    def __len__(self):
        return len(self.__b)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return strarray(self.__b[i])
        return self.__b[i]

    def append(self, s):
        self.__b.append(self._ordize(s))

    def extend(self, s):
        self.__b.extend(self._ordize(i) for i in s)

    def __str__(self):
        return "".join(chr(i) for i in self.__b)


class WebSocketFile:
    """WebSocket file class"""

    def __init__(self, websocket):
        self.websocket = websocket
        if websocket.mode == "t":
            self.buffer = strarray()
        elif websocket.mode == "b":
            self.buffer = bytearray()
        else:
            raise ValueError(
                "can't establish a WebSocket file using WebSocket in flexible mode"
            )
        self.mode = websocket.mode
        self.position = 0
        self.closed = False

    def seek(self, position):
        """Moves the cursor to a different position"""
        self.position = position

    def tell(self):
        """Returns the cursor position"""
        return self.position

    def close(self):
        """Closes the Websocket"""
        self.websocket.close()
        self.closed = True

    def read(self, b=None):
        """Reads from the Websocket
        :param b: Number of bytes to read. If `None` - reads until the end of buffer(if the buffer is empty, reads entire new frame)
        :type b:`int` or `None`
        """
        r = self._read(b)
        if isinstance(r, strarray):
            return str(r)
        elif isinstance(r, bytearray):
            return bytes(r)
        elif isinstance(r, int):
            if self.mode == "t":
                return chr(r)
            return r

    def _read(self, b=None):
        if b is None:
            if self.position == len(self.buffer):
                self.buffer.extend(self.websocket.recv())
            r = self.buffer[self.position :]
            self.position = len(self.buffer)
            return r
        while len(self.buffer[self.position : self.position + b]) < b:
            self.buffer.extend(self.websocket.recv())
        r = self.buffer[self.position : self.position + b]
        self.position += b
        return r

    def write(self, what):
        """Writes to the WebSocket"""
        self.websocket.send(what)


class WebSocket:
    def __init__(
        self, url, mode="", debug=False, use_tls=None, subprotocol=None, origin=None
    ):
        """
        :param url: Url for WebSocket
        :type url: str
        :param debug: Specifies whether or not to use the debug mode
        :type debug: str
        :param use_tls: Specifies wheter or not to use TLS for the WebSocket
        :param subprotocol: Subprotocol to use, defaults to `None`
        :type subprotocol: str or None
        :param mode: Specifies default mode for the WebSocket. Possible values:`'t'` for textual `'b'` for binary or `''` to decide automatically.
        :type mode: str
        :param origin: Origin of request, defaults to `None`
        :type origin: str or None
        """
        self.mode = mode
        if self.mode and self.mode not in "tb":
            raise ValueError("invalid mode")
        self.url = url
        self.closed = False
        self.use_tls = use_tls if use_tls is not None else url.split("://")[0] == "wss"
        self.port = 443 if use_tls else 80
        self.debug = debug
        self.subprotocol = subprotocol
        self.origin = origin
        self.debugger = _Debugger(debug)
        self.key = generate_websocket_key()
        self.base_url = url.split("://")[-1]
        self.http_url = f"http{'s' if use_tls else ''}://{self.base_url}"
        del default_session[get_host(self.http_url), self.port]
        self.handshake_response = websocket_handshake(
            self.http_url, self.key, self.debugger
        )
        self.debugger.info("extracting socket")
        self.socket = self.handshake_response.request.socket

    def _fail(self, message):
        self.debugger.error(f"{message}, failing connection")
        self.close_with_errcode(1002, message)

    def _recv_frame(self):
        if self.closed:
            raise RuntimeError("WebSocket is closed.")
        fb = ord(self.socket.recv(1))
        fin = bool(fb & 0b10000000)
        self.debugger.info(f"Final: {fin}")

        rsvok = not fb & 0b01110000
        if not rsvok:
            self._fail("Invalid reserved bits")
            return
        opcode = fb & 0b00001111
        self.debugger.info(f"Opcode: {hex(opcode)}")
        if opcode not in WEBSOCKET_OPCODES:
            self._fail(f"Unknown opcode {hex(opcode)}")
        sb = ord(self.socket.recv(1))
        masked = bool(sb & 0b10000000)
        self.debugger.info(f"Masked: {masked}")
        ln = sb & 0b01111111
        if ln <= 125:
            payload_length = ln
        elif ln == 126:
            next2bytes = self.socket.recv(2)
            payload_length = _int16unpk(next2bytes)
        elif ln == 127:
            next8bytes = self.socket.recv(8)
            (payload_length,) = struct.unpack("!Q", next8bytes)
        self.debugger.info(f"Length: {payload_length} bytes")
        if masked:
            masking_key = self.socket.recv(4)
            self.debugger.info("Masking key: {masking_key}")
        self.debugger.info("Receiving payload")
        payload = self.socket.recv(payload_length)
        if masked:
            self.debugger.info("Unmasking")
            payload = mask(payload, masking_key)
        if not fin:  # continuation
            debugger.info("Not a final frame, continuing")
            p, o = self._recv_frame()
            payload += p
            if o != 0:
                self._fail(f"Expected opcode 0x0 ,got {hex(o)}")
        return payload, opcode

    def reconnect(self):
        self.close()
        return WebSocket(
            self.url, self.mode, self.debug, self.use_tls, self.subprotocol, self.origin
        )

    def makefile(self):
        return WebSocketFile(self)

    def send(self, data):
        """Sends data to WebSocket server

        :param data: Data to send to the server
        :type data: str or bytes
        """
        payload, opcode = self._opcode_unparse(data)
        self._send_frame(opcode, payload)

    def recv(self):
        """Receives data from WebSocket server"""
        payload, opcode = self._recv_frame()
        return self._opcode_parse(payload, opcode)

    def close(self):
        """Closes the WebSocket connection with close code of 1000"""
        if not self.closed:
            self.close_with_errcode(1000, "")

    def _send_frame(self, opcode, payload, final=True):
        if self.closed:
            raise RuntimeError("WebSocket is closed.")

        self.debugger.info("building header")
        header_1 = (int(final) * (0b10000000)) | opcode
        self.debugger.info(f"First part: {bin(header_1)}")

        payload_length = len(payload)
        self.debugger.info("selecting masking key")
        masking_key = os.urandom(4)
        message = io.BytesIO()
        self.debugger.info("Encoding payload length")
        if payload_length <= 125:
            message.write(struct.pack("!BB", header_1, 0b10000000 | payload_length))
        elif payload_length <= 65535:
            message.write(
                struct.pack("!BBH", header_1, 0b10000000 | 126, payload_length)
            )
        elif payload_length <= 18446744073709551615:
            message.write(
                struct.pack("!BBQ", header_1, 0b10000000 | 127, payload_length)
            )
        else:
            raise OverflowError(
                f"Length of payload exceeded {18446744073709551615:,} bytes"
            )
        message.write(masking_key)
        self.debugger.info("Masking payload")
        message.write(mask(payload, masking_key))
        self.debugger.info("Sending")
        self.socket.send(message.getvalue())

    def close_with_errcode(self, close_code, message):
        if close_code == 1000:
            self.debugger.info("Closing connection.")
        else:
            self.debugger.error(
                f"Server error: {close_code} {WEBSOCKET_CLOSE_CODES[close_code]}, {message}"
            )
        self._send_frame(0x8, int2bytes(close_code) + force_bytes(message))
        self.debugger.info("Closing underlying TCP conn")
        self.socket.close()
        self.closed = True

    def _server_close(self, close_code, message):
        if close_code == 1000:
            self.debugger.info(
                "Received 0x8 CLOSE, exitting. Close code: 1000 Normal closure"
            )
            self.close_with_errcode(close_code, message)
            return
        else:
            self.debugger.error(
                f"Received erroneous close code: {close_code} {WEBSOCKET_CLOSE_CODES[close_code]}, {message}"
            )
            self.close_with_errcode(close_code, message)
            raise WebSocketClientError(
                f"{close_code} {WEBSOCKET_CLOSE_CODES[close_code]} : {message}"
            )

    def _opcode_parse(self, data, opcode):
        debugger.info("Parsing opcode")
        if opcode == 0x8:
            close_code = int.from_bytes(data[:2], "big")
            self._server_close(close_code, data[2:])
        elif opcode == 0x1:
            if self.mode == "t":
                try:
                    return data.decode("UTF-8")
                except UnicodeDecodeError:  # expected
                    raise TypeError(
                        "undecodeable binary data sent to client in binary mode"
                    )
            return data
        elif opcode == 0x2:
            if self.mode == "b":
                return data
            return data.decode("UTF-8")
        elif opcode == 0x0:
            self._fail("Continuation frame after final frame")

    def _opcode_unparse(self, data):
        if isinstance(data, bytes):
            if self.mode == "t":
                raise TypeError("You can't send binary data in textual mode")
            return data, 0x1
        if isinstance(data, str):
            if self.mode == "b":
                raise TypeError("You can't send textual data in binary mode")
            return data.encode("UTF-8"), 0x2
        raise TypeError(
            f"Unsupported data type : {type(data).__name__!r}, please use either str or bytes."
        )


atexit.register(close_all)
