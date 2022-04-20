#  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
#  APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
#  HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
#  OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#  PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
#  IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
#  ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
"""
HTTPy is a lightweight socket-based HTTP client.
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
import ctypes  # to get errno
import struct  # to pack floats
import hashlib  # for Digest auth
import builtins  # for debugging
import inspect  # for debugging
import sys  # for debugging

try:
    import chardet  # to detect charsets
except ImportError:
    chardet = None

HTTPY_DIR = pathlib.Path.home() / ".cache/httpy"
os.makedirs(HTTPY_DIR / "sites", exist_ok=True)
VERSION = "1.1.3"
URLPATTERN = re.compile(
    r"^(?P<scheme>[a-z]+)://(?P<host>[^/:]*)(:(?P<port>(\d+)?))?/?(?P<path>.*)$"
)
STATUSPATTERN = re.compile(
    rb"(?P<VERSION>.*)\s*(?P<status>\d{3})\s*(?P<reason>[^\r\n]*)"
)
STATUS_CODES = {
    "100": {
        "code": "100",
        "message": "Continue",
        "description": "indicates that the initial part of a request has been received and has not yet been rejected by the server.",
    },
    "101": {
        "code": "101",
        "message": "Switching Protocols",
        "description": "indicates that the server understands and is willing to comply with the client's request, via the Upgrade header field, for a change in the application protocol being used on this connection.",
    },
    "200": {
        "code": "200",
        "message": "OK",
        "description": "indicates that the request has succeeded.",
    },
    "201": {
        "code": "201",
        "message": "Created",
        "description": "indicates that the request has been fulfilled and has resulted in one or more new resources being created.",
    },
    "202": {
        "code": "202",
        "message": "Accepted",
        "description": "indicates that the request has been accepted for processing, but the processing has not been completed.",
    },
    "203": {
        "code": "203",
        "message": "Non-Authoritative Information",
        "description": "indicates that the request was successful but the enclosed payload has been modified from that of the origin server's 200 (OK) response by a transforming proxy.",
    },
    "204": {
        "code": "204",
        "message": "No Content",
        "description": "indicates that the server has successfully fulfilled the request and that there is no additional content to send in the response payload body.",
    },
    "205": {
        "code": "205",
        "message": "Reset Content",
        "description": "indicates that the server has fulfilled the request and desires that the user agent reset the document view, which caused the request to be sent, to its original state as received from the origin server.",
    },
    "206": {
        "code": "206",
        "message": "Partial Content",
        "description": "indicates that the server is successfully fulfilling a range request for the target resource by transferring one or more parts of the selected representation that correspond to the satisfiable ranges found in the requests's Range header field.",
    },
    "300": {
        "code": "300",
        "message": "Multiple Choices",
        "description": "indicates that the target resource has more than one representation, each with its own more specific identifier, and information about the alternatives is being provided so that the user (or user agent) can select a preferred representation by redirecting its request to one or more of those identifiers.",
    },
    "301": {
        "code": "301",
        "message": "Moved Permanently",
        "description": "indicates that the target resource has been assigned a new permanent URI and any future references to this resource ought to use one of the enclosed URIs.",
    },
    "302": {
        "code": "302",
        "message": "Found",
        "description": "indicates that the target resource resides temporarily under a different URI.",
    },
    "303": {
        "code": "303",
        "message": "See Other",
        "description": "indicates that the server is redirecting the user agent to a different resource, as indicated by a URI in the Location header field, that is intended to provide an indirect response to the original request.",
    },
    "304": {
        "code": "304",
        "message": "Not Modified",
        "description": "indicates that a conditional GET request has been received and would have resulted in a 200 (OK) response if it were not for the fact that the condition has evaluated to false.",
    },
    "305": {
        "code": "305",
        "message": "Use Proxy",
        "description": "*deprecated*",
    },
    "307": {
        "code": "307",
        "message": "Temporary Redirect",
        "description": "indicates that the target resource resides temporarily under a different URI and the user agent MUST NOT change the request method if it performs an automatic redirection to that URI.",
    },
    "400": {
        "code": "400",
        "message": "Bad Request",
        "description": "indicates that the server cannot or will not process the request because the received syntax is invalid, nonsensical, or exceeds some limitation on what the server is willing to process.",
    },
    "401": {
        "code": "401",
        "message": "Unauthorized",
        "description": "indicates that the request has not been applied because it lacks valid authentication credentials for the target resource.",
    },
    "402": {
        "code": "402",
        "message": "Payment Required",
        "description": "*reserved*",
    },
    "403": {
        "code": "403",
        "message": "Forbidden",
        "description": "indicates that the server understood the request but refuses to authorize it.",
    },
    "404": {
        "code": "404",
        "message": "Not Found",
        "description": "indicates that the origin server did not find a current representation for the target resource or is not willing to disclose that one exists.",
    },
    "405": {
        "code": "405",
        "message": "Method Not Allowed",
        "description": "indicates that the method specified in the request-line is known by the origin server but not supported by the target resource.",
    },
    "406": {
        "code": "406",
        "message": "Not Acceptable",
        "description": "indicates that the target resource does not have a current representation that would be acceptable to the user agent, according to the proactive negotiation header fields received in the request, and the server is unwilling to supply a default representation.",
    },
    "407": {
        "code": "407",
        "message": "Proxy Authentication Required",
        "description": "is similar to 401 (Unauthorized), but indicates that the client needs to authenticate itself in order to use a proxy.",
    },
    "408": {
        "code": "408",
        "message": "Request Timeout",
        "description": "indicates that the server did not receive a complete request message within the time that it was prepared to wait.",
    },
    "409": {
        "code": "409",
        "message": "Conflict",
        "description": "indicates that the request could not be completed due to a conflict with the current state of the resource.",
    },
    "410": {
        "code": "410",
        "message": "Gone",
        "description": "indicates that access to the target resource is no longer available at the origin server and that this condition is likely to be permanent.",
    },
    "411": {
        "code": "411",
        "message": "Length Required",
        "description": "indicates that the server refuses to accept the request without a defined Content-Length.",
    },
    "412": {
        "code": "412",
        "message": "Precondition Failed",
        "description": "indicates that one or more preconditions given in the request header fields evaluated to false when tested on the server.",
    },
    "413": {
        "code": "413",
        "message": "Payload Too Large",
        "description": "indicates that the server is refusing to process a request because the request payload is larger than the server is willing or able to process.",
    },
    "414": {
        "code": "414",
        "message": "URI Too Long",
        "description": "indicates that the server is refusing to service the request because the request-target is longer than the server is willing to interpret.",
    },
    "415": {
        "code": "415",
        "message": "Unsupported Media Type",
        "description": "indicates that the origin server is refusing to service the request because the payload is in a format not supported by the target resource for this method.",
    },
    "416": {
        "code": "416",
        "message": "Range Not Satisfiable",
        "description": "indicates that none of the ranges in the request's Range header field overlap the current extent of the selected resource or that the set of ranges requested has been rejected due to invalid ranges or an excessive request of small or overlapping ranges.",
    },
    "417": {
        "code": "417",
        "message": "Expectation Failed",
        "description": "indicates that the expectation given in the request's Expect header field could not be met by at least one of the inbound servers.",
    },
    "418": {
        "code": "418",
        "message": "I'm a teapot",
        "description": "Any attempt to brew coffee with a teapot should result in the error code 418 I'm a teapot.",
    },
    "426": {
        "code": "426",
        "message": "Upgrade Required",
        "description": "indicates that the server refuses to perform the request using the current protocol but might be willing to do so after the client upgrades to a different protocol.",
    },
    "500": {
        "code": "500",
        "message": "Internal Server Error",
        "description": "indicates that the server encountered an unexpected condition that prevented it from fulfilling the request.",
    },
    "501": {
        "code": "501",
        "message": "Not Implemented",
        "description": "indicates that the server does not support the functionality required to fulfill the request.",
    },
    "502": {
        "code": "502",
        "message": "Bad Gateway",
        "description": "indicates that the server, while acting as a gateway or proxy, received an invalid response from an inbound server it accessed while attempting to fulfill the request.",
    },
    "503": {
        "code": "503",
        "message": "Service Unavailable",
        "description": "indicates that the server is currently unable to handle the request due to a temporary overload or scheduled maintenance, which will likely be alleviated after some delay.",
    },
    "504": {
        "code": "504",
        "message": "Gateway Time-out",
        "description": "indicates that the server, while acting as a gateway or proxy, did not receive a timely response from an upstream server it needed to access in order to complete the request.",
    },
    "505": {
        "code": "505",
        "message": "HTTP Version Not Supported",
        "description": "indicates that the server does not support, or refuses to support, the protocol version that was used in the request message.",
    },
    "102": {
        "code": "102",
        "message": "Processing",
        "description": "is an interim response used to inform the client that the server has accepted the complete request, but has not yet completed it.",
    },
    "207": {
        "code": "207",
        "message": "Multi-Status",
        "description": "provides status for multiple independent operations.",
    },
    "226": {
        "code": "226",
        "message": "IM Used",
        "description": "The server has fulfilled a GET request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance.",
    },
    "308": {
        "code": "308",
        "message": "Permanent Redirect",
        "description": "The target resource has been assigned a new permanent URI and any future references to this resource outght to use one of the enclosed URIs. [...] This status code is similar to 301 Moved Permanently (Section 7.3.2 of rfc7231), except that it does not allow rewriting the request method from POST to GET.",
    },
    "422": {
        "code": "422",
        "message": "Unprocessable Entity",
        "description": "means the server understands the content type of the request entity (hence a 415(Unsupported Media Type) status code is inappropriate), and the syntax of the request entity is correct (thus a 400 (Bad Request) status code is inappropriate) but was unable to process the contained instructions.",
    },
    "423": {
        "code": "423",
        "message": "Locked",
        "description": "means the source or destination resource of a method is locked.",
    },
    "424": {
        "code": "424",
        "message": "Failed Dependency",
        "description": "means that the method could not be performed on the resource because the requested action depended on another action and that action failed.",
    },
    "428": {
        "code": "428",
        "message": "Precondition Required",
        "description": "indicates that the origin server requires the request to be conditional.",
    },
    "429": {
        "code": "429",
        "message": "Too Many Requests",
        "description": "indicates that the user has sent too many requests in a given amount of time (rate limiting).",
    },
    "431": {
        "code": "431",
        "message": "Request Header Fields Too Large",
        "description": "indicates that the server is unwilling to process the request because its header fields are too large.",
    },
    "451": {
        "code": "451",
        "message": "Unavailable For Legal Reasons",
        "description": "This status code indicates that the server is denying access to the resource in response to a legal demand.",
    },
    "506": {
        "code": "506",
        "message": "Variant Also Negotiates",
        "description": "indicates that the server has an internal configuration error: the chosen variant resource is configured to engage in transparent content negotiation itself, and is therefore not a proper end point in the negotiation process.",
    },
    "507": {
        "code": "507",
        "message": "Insufficient Storage",
        "description": "means the method could not be performed on the resource because the server is unable to store the representation needed to successfully complete the request.",
    },
    "511": {
        "code": "511",
        "message": "Network Authentication Required",
        "description": "indicates that the client needs to authenticate to gain network access.",
    },
}
context = ssl.create_default_context()
schemes = {"http": 80, "https": 443}


class HTTPyError(Exception):
    """A metaclass for all HTTPy Exceptions."""


class AuthError(HTTPyError):
    """Error in authentication"""


class ConnectionClosedError(HTTPyError, ConnectionError):
    """Connection Closed"""


class ConnectionLimitError(HTTPyError, ConnectionError):
    """Connection Limit reached"""


class ConnectionExpiredError(HTTPyError, ConnectionError, TimeoutError):
    """Connection Expired"""


class ServerError(HTTPyError):
    """Raised if server is not found"""


class TooManyRedirectsError(HTTPyError):
    """Raised if server has responded with too many redirects (over redirection limit)"""


def _mk2l(original):
    if len(original) == 1:
        original.append(True)
    return original


class Status(int):
    """
    Creates HTTP status from string.

    :param statstring: string to parse
    """

    def __init__(self, statstring):
        _, self.status, self.reason = STATUSPATTERN.search(statstring).groups()
        self.status = int(self.status)
        try:
            self.codes_entry = STATUS_CODES[str(self.status)]
        except KeyError:
            self.codes_entry = {
                "code": str(self.status),
                "message": "Unknown",
                "description": "Unknown",
            }
        self.__dict__.update(self.codes_entry)

        self.reason = self.reason.decode()

    def __new__(cls, statstring):
        _, status, reason = STATUSPATTERN.search(statstring).groups()
        return super(Status, cls).__new__(cls, status)


class _Debugger:
    """
    Debugger
    """

    def __init__(self, do_debug=None):
        self._debug = do_debug

    def frame_class_name(self, fr):
        args, _, _, value_dict = inspect.getargvalues(fr)
        if len(args) and args[0] == "self":
            instance = value_dict.get("self", None)
            if instance:
                return getattr(getattr(instance, "__class__", None), "__name__", None)
        return None

    @property
    def debug(self):
        return self._debug or getattr(builtins, "debug", False)

    def debugging_method(self, suffix):
        def decorated(a, data):
            if a.debug:
                fr = inspect.currentframe().f_back
                class_name = a.frame_class_name(fr)

                sys.stdout.write(self)
                if class_name:
                    sys.stdout.write(class_name)
                sys.stdout.write("[")
                sys.stdout.write(fr.f_code.co_name)
                sys.stdout.write("]")
                sys.stdout.write("(")
                sys.stdout.write(str(inspect.getframeinfo(fr).lineno))
                sys.stdout.write(")")
                sys.stdout.write(": ")
                sys.stdout.write(data)
                sys.stdout.write(suffix)
                sys.stdout.write("\r\n")

        return decorated

    info = debugging_method("\033[94m[INFO]", "\033[0m")
    ok = debugging_method("\033[92m[OK]", "\033[0m")
    warn = debugging_method("\033[93m[WARN]", "\033[0m")


class CaseInsensitiveDict(dict):
    """Case insensitive subclass of dictionary"""

    def __init__(self, data):
        self.original = {force_string(k).lower(): v for k, v in dict(data).items()}
        super().__init__(self.original)

    def __contains__(self, item):
        return force_string(item).lower() in self.original

    def __getitem__(self, item):
        return self.original[force_string(item).lower()]

    def __setitem__(self, item, val):
        self.original[force_string(item).lower()] = val
        super().__init__(self.original)  # remake??

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    def __iter__(self):
        return iter(self.original)

    def keys(self):
        return self.original.keys()

    def values(self):
        return self.original.values()

    def items(self):
        return self.original.items()


def _binappendstr(s):
    return bytes([len(s)]) + force_bytes(s)


def _binappendfloat(b):
    b = float(b)
    ba = struct.pack("f", b)
    return bytes([len(ba)]) + ba


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
        srl = ord(file.read(1))
        sl = file.read(srl)
        self.status = Status(sl)
        self.url = os.path.split(f)[-1].replace("\x01", "://").replace("\x02", "/")
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

    def __init__(self, d=HTTPY_DIR / "sites"):
        self.dir = d
        self.files = [CacheFile(os.path.join(d, i)) for i in os.listdir(d)]

    def updateCache(self):
        """Updates self.files according to /sites directory content and removes expired ones"""
        for file in self.files:
            if file.expired:
                os.remove(
                    os.path.join(
                        self.dir, file.url.replace("://", "\x01").replace("/", "\x02")
                    )
                )
        self.files = [
            CacheFile(os.path.join(self.dir, i)) for i in os.listdir(self.dir)
        ]

    def __getitem__(self, u):
        self.updateCache()  # ...
        for f in self.files:
            if reslash(f.url) == reslash(u):
                return f
        return None

    def __contains__(self, u):
        return self[u] is not None


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
            data += b"\x00"
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
        kvpl = ord(buffer.read(1))
        k, v = buffer.read(kvpl).split(b"=", 1)
        hostl = ord(buffer.read(1))
        data = {}
        if hostl > 0:
            data["Host"] = buffer.read(hostl).decode()
        pl = buffer.read(1)
        p = buffer.read(ord(pl))
        data["Path"] = p
        n = buffer.read(1)
        if n == b"\x01":
            data["Secure"] = True
            n = buffer.read(1)
        if n == b"\x00":
            expires = None
        else:
            tstamp = buffer.read(ord(n))
            expires = _unpk_float(tstamp)
            data["Expires"] = expires
        return Cookie(k.decode(), v.decode(), data, host)


class CookieDomain:
    "Class for domain that stores cookies"

    def __init__(self, content, jar):
        self.content = content
        bio = io.BytesIO(content)
        nl = ord(bio.read(1))
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
    """Class for cookie jar"""

    def __init__(self, jarfile=HTTPY_DIR / "CookieJar"):
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


class File(io.IOBase):
    """Class  used to upload files"""

    def __init__(self, buffer, filename, content_type=None):
        self.parent = super().__init__()
        if content_type is None:
            content_type = force_string(
                mimetypes.guess_type(os.path.split(filename)[1])[0]
            )
        content_type = force_string(content_type)

        self.size = len(buffer)
        self.buffer = io.BytesIO(buffer)

        self.name = force_string(os.path.split(filename)[1])
        self.mode = "rb"
        self.content_type = content_type

    def read(self, size=-1):
        return self.buffer.read(size)

    def save(self, destination):
        if os.path.exists(destination):
            if os.path.isdir(destination):
                destination = os.path.join(destination, self.name)

        return open(destination, "wb").write(self.buffer.getvalue())

    def seek(self, pos):
        self.buffer.seek(pos)

    def tell(self):
        return self.buffer.tell()

    def write(self, anything):
        raise io.UnsupportedOperation("not writable")

    def value(self):
        return self.buffer.getvalue()

    @classmethod
    def open(self, file):
        reader = open(file, "rb")
        return File(reader.read(), file)


class Headers(CaseInsensitiveDict):
    """Class for HTTP headers"""

    def __init__(self, h):
        h = filter(lambda x: x, h)
        self.headers = (
            [
                a.split(b": ", 1)[0].lower().decode(),
                a.split(b": ", 1)[1].decode().strip(),
            ]
            for a in h
        )
        self.headers = mkdict(self.headers)
        super().__init__(self.headers)

    def __setitem__(self, item, value):
        raise NotImplementedError


class Response:
    """
    Class for HTTP Response.

    :param status: Status returned by server
    :type status: Status
    :ivar status: Status returned by server
    :param headers: Headers attached to the document
    :type headers: Headers
    :ivar headers: Headers attached to the document
    :param content: Document content
    :type content: bytes
    :ivar content: Document content
    :param history: Response history
    :type history: list
    :ivar history: Response history
    :param fromcache: Indicates whether or not  was response loaded from cache
    :type fromcache: bool
    :ivar fromcache: Indicates whether or not was response loaded from cache
    :ivar charset: Document charset
    :ivar speed: Average download speed in bytes per second
    :type speed: float
    :param original_content: Document content before any Content-Encoding was applied.
    :type original_content: bytes
    :param time_elapsed: Total request time
    :type time_elapsed: float
    :ivar ok: `self.status==200`
    """

    def __init__(
        self,
        status,
        headers,
        content,
        history,
        url,
        fromcache,
        original_content,
        time_elapsed=math.inf,
    ):
        self.status = status
        self.headers = headers
        self.content = content
        self.ok = self.status == 200
        self.reason=self.status.reason
        self._original = original_content
        self.speed = len(self._original) / time_elapsed
        self.url = reslash(url)
        self.fromcache = fromcache
        self._time_elapsed = time_elapsed

        if not self.fromcache and (self.content or self.headers or self.status):
            cacheWrite(self)

        self._charset = determine_charset(headers)
        self.history = history
        self.history.append(self)

    @classmethod
    def cacheload(self, cache_file):
        """
        Loads response from CacheFile.

        :param cache_file: CacheFile to load from
        :type cache_file: CacheFile
        """
        return Response(
            cache_file.status,
            cache_file.headers,
            cache_file.body,
            [],
            cache_file.url,
            True,
            cache_file.content,
            cache_file.time_elapsed,
        )

    @classmethod
    def plain(self):
        return Response(Status(b"000"), Headers({}), b"", [], "", False, b"")

    @property
    def charset(self):
        if self._charset is None and chardet is not None:
            self._charset = chardet.detect(self.content)["encoding"]
        return self._charset

    def __repr__(self):
        return f"<Response [{self.status} {self.reason}] ({self.url})>"


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
        self.params = CaseInsensitiveDict(real)

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


class Connection:
    """Class for connnections"""

    def __init__(self, sock, timeout=math.inf, max=math.inf):
        debugger.info(f"Created new Connection upon {sock}")
        self._sock = sock
        self.timeout = timeout
        self.max = math.inf
        self.requests = 0
        self.time_started = time.time()

    @property
    def sock(self):
        self.requests += 1
        if self.time_started + self.timeout < time.time():
            debugger.warn(f"Connection expired")
            raise ConnectionExpiredError("Connection expired")
        if self.requests > self.max:
            debugger.warn(f"Connection limit reached")
            raise ConnectionLimitError("connection limit reached")
        return self._sock

    def close(self):
        self._sock.close()


class ConnectionPool:
    """Class for connection pools"""

    def __init__(self):
        self.connections = {}

    def __setitem__(self, host, connection):
        host, port = host
        if connection._sock.fileno() == -1:
            raise ConnectionClosedError("Connection closed by host")
        self.connections[host, port] = connection

    def __getitem__(self, host):
        try:

            sock = self.connections[host].sock
        except ConnectionError:
            del self.connection[host]

            raise ConnectionClosedError("Connection closed by host")
        if sock.fileno() == -1:
            del self.connections[host]
            raise ConnectionClosedError("Connection closed by host")
        return sock

    def __contains__(self, host):
        return host in self.connections

    def __delitem__(self, host):
        del self.connections[host]

    def __del__(self):
        for conn in self.connections.values():
            conn.close()


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


md5, sha256, sha512 = (hashing_function(i) for i in ("md5", "sha256", "sha512"))
ALGORITHMS = {"md5": md5, "sha256": sha256, "sha512": sha512}


def cacheWrite(response):
    """
    Writes response to cache

    :param response: response to save
    :type response: Response"""
    data = b""
    data += _binappendfloat(time.time())
    data += _binappendfloat(response._time_elapsed)
    data += _binappendstr(f"{response.status:03} {response.reason}")
    data += "\r".join([mk_header(i) for i in response.headers.headers.items()]).encode()
    data += b"\x00"
    data += response.content

    with open(
        HTTPY_DIR
        / "sites"
        / (response.url.replace("://", "\x01").replace("/", "\x02")),
        "wb",
    ) as f:
        f.write(gzip.compress(data))


def mkdict(kvp):
    """Makes dict from key/value pairs"""
    d = {}
    for k, v in kvp:
        k = k.lower()
        if k in d:
            if isinstance(d[k], list):
                d[k].append(v)
            else:
                d[k] = [d[k]] + [v]
        else:
            d[k] = v
    return d


def urlencode(data):
    """Creates urlencoded string from dict data"""
    return b"&".join(b"=".join(force_bytes(i) for i in x) for x in data.items())


def _gzip_decompress(data):
    return gzip.GzipFile(fileobj=io.BytesIO(data)).read()


def _zlib_decompress(data):
    return zlib.decompress(data, -zlib.MAX_WBITS)


def _generate_boundary():
    return (
        b"--"
        + "".join(random.choices(string.ascii_letters + string.digits, k=10)).encode()
        + b"\r\n"
    )


def force_string(anything):
    """Converts string or bytes to string"""
    try:
        if isinstance(anything, str):
            return anything
        if isinstance(anything, bytes):
            return anything.decode()
    except Exception as err:
        debugger.warn(f"Could not decode {anything}")
    return str(anything)


def force_bytes(anything):
    """Converts bytes or string to bytes"""
    if isinstance(anything, bytes):
        return anything
    if isinstance(anything, str):
        return anything.encode()
    if isinstance(anything, int):
        return force_bytes(str(anything))
    return bytes(anything)


def get_content_type(data):
    """Used to automatically get request content type"""
    if isinstance(data, bytes):
        return "application/octet-stream"
    elif isinstance(data, str):
        return "text/plain"
    elif isinstance(data, dict):
        for x in data.values():
            if isinstance(x, File):
                return "multipart/form-data"
        return "application/x-www-form-urlencoded"
    raise TypeError(
        "could not get content type(can encode only bytes,str and dict). Please specify raw data and set content_type argument"
    )


def _unpk_float(bs):
    return struct.unpack("f", bs)[0]


def multipart(form, boundary=_generate_boundary()):
    """Builds multipart/form-data from form"""
    built = b""
    for i in form.items():
        built += boundary
        disp = b'Content-Disposition: form-data; name="' + force_bytes(i[0]) + b'"'
        val = i[1]
        if isinstance(val, File):
            disp += b'; filename="' + force_bytes(val.name) + b'"'
            val = val.read()
        disp += b"\r\n\r\n"
        val = force_bytes(val)
        disp += val
        disp += b"\r\n"
        built += disp
    built += boundary.strip() + b"--\r\n"
    return built, "multipart/form-data; boundary=" + boundary[2:].strip().decode()


def _encode_form_data(data, content_type=None):
    if content_type is None:
        debugger.info("no content_type specified, getting automatically")
        content_type = get_content_type(data)
    if content_type in ("text/plain", "application/octet-stream"):
        debugger.info("content_type text/plain or application/octet-stream")
        return force_bytes(data), content_type
    elif content_type == "application/x-www-form-urlencoded":
        debugger.info("content_type urlencoded")
        return urlencode(data), content_type
    elif content_type == "multipart/form-data":
        debugger.info("content_type multipart")
        return multipart(data)
    elif content_type == "application/json":
        debugger.info("content_type json")
        return json.dumps(data).encode(), content_type
    debugger.warn("unknown content_type")
    return force_bytes(data), content_type


def encode_form_data(data, content_type=None):
    """Encodes form data according to content type"""

    encoded, content_type = _encode_form_data(data, content_type)
    return force_bytes(encoded), {
        "Content-Type": content_type,
        "Content-Length": len(encoded),
    }


def determine_charset(headers):
    """Gets charset from headers"""
    if "Content-Type" in headers:
        charset = headers["Content-Type"].split(";")[-1].strip()
        if not charset.startswith("charset"):
            return None
        return charset.split("=")[-1].strip()
    return None


def chain_functions(funs):
    """Chains functions . Called by get_encoding_chain()"""

    def chained(r):
        for fun in funs:
            r = fun(r)
        return r

    return chained


def get_encoding_chain(encoding):
    """Gets decoding chain from Content-Encoding"""
    encds = encoding.split(",")
    return chain_functions(encodings[enc.strip()] for enc in encds)


def decode_content(content, encoding):
    """Decodes content with get_encoding_chain()"""
    try:
        return get_encoding_chain(encoding)(content)
    except:
        return content


def makehost(host, port):
    """Creates hostname from host and port"""
    if int(port) in [443, 80]:
        return host
    return host + ":" + str(port)


def reslash(url):
    """Adds trailing slash to the end of URL"""
    url = force_string(url)
    if url.endswith("/"):
        return url
    return url + "/"


def deslash(url):
    """Removes trailing slash from the end of URL"""
    url = force_string(url)
    if url.endswith("/"):
        return url[:-1]
    return url


def generate_cnonce(length=16):
    debugger.info("generating cnonce")
    return hex(random.randrange(16**length))[2:]


def mk_header(key_value_pair):
    """Makes header from key/value pair"""
    if isinstance(key_value_pair[1], list):
        header = ""
        for key_value in key_value_pair[1]:
            header += key_value_pair[0] + ": " + key_value + "\r\n"
        return header.strip()
    return ": ".join([force_string(key_value) for key_value in key_value_pair])


def _debugprint(debug, what, *args, **kwargs):
    if debug:
        print(force_string(what), *args, **kwargs)


def create_connection(host, port, last_response):
    keep_alive = KeepAlive(last_response.headers.get("keep-alive", ""))
    if (host, port) in pool:
        debugger.info("Connection already in pool")
        try:
            return pool[host, port], True
        except ConnectionClosedError:
            debugger.warn("Connection already expired.")
    try:
        debugger.info("calling socket.create_connection")
        conn = socket.create_connection((host, port))
    except socket.gaierror:
        debugger.warn("gaierror raised, getting errno")
        # Get errno using ctypes, check for  -2(-3)
        errno = ctypes.c_int.in_dll(ctypes.pythonapi, "errno").value
        if errno in [2, 3]:
            raise ServerError(f"could not find server {host!r}")
        debugger.warn(f"unknown errno {errno!r}")
        raise  # Added in 1.1.1
    pool[host, port] = Connection(conn, keep_alive.timeout, keep_alive.max)
    return conn, False


def _raw_request(
    host,
    port,
    path,
    scheme,
    url="",
    method="GET",
    data=b"",
    content_type=None,
    timeout=32,
    headers={},
    auth={},
    history=[],
    debug=False,
    last_status=-1,
):
    debug = debug or getattr(builtins,'debug',False)
    debugger.info("_raw_request() called.")
    debugger.info("Accessing cache.")
    cf = cache[deslash(url)]
    socket.setdefaulttimeout(timeout)
    if cf and not cf.expired:
        debugger.info("Not expired data in cache, loading from cache")
        return Response.cacheload(cf)
    else:
        debugger.info("No data in cache.")
    defhdr = {
        "Accept-Encoding": "gzip, deflate, identity",
        "Host": makehost(host, port),
        "User-Agent": "httpy/" + VERSION,
        "Connection": "keep-alive",
    }

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
    cookies = jar.get_cookies(makehost(host, port), scheme, path)
    if cookies:
        defhdr["Cookie"] = []
        for c in cookies:
            defhdr["Cookie"].append(c.name + "=" + c.value)

    defhdr.update(headers)
    debugger.info("Establishing connection ")
    if history:
        last_response = history[-1]
    else:
        last_response = Response.plain()
    sock, from_pool = create_connection(host, port, last_response)
    start_time = time.time()

    try:
        if scheme == "https" and not from_pool:
            sock = context.wrap_socket(sock, server_hostname=host)

        defhdr.update(headers)
        if cf:
            cf.add_header(defhdr)
        headers = "\r\n".join([mk_header(i) for i in defhdr.items()])
        request_data = f"{method} {path} HTTP/1.1" + "\r\n"
        request_data += headers
        _debugprint(debug, "\nsend:\n" + request_data)
        request_data += "\r\n\r\n"
        request_data = request_data.encode()
        sock.send(request_data)
        sock.send(data)
        file = sock.makefile("b")
        statusline = file.readline()
        _debugprint(debug, "\nresponse: ")
        _debugprint(debug, statusline)
        status = Status(statusline)
        if status.status == 304:
            return Response.cacheload(cf)
        headers = []
        while True:
            line = file.readline()
            if line == b"\r\n":
                break
            _debugprint(debug, line.decode(), end="")
            headers.append(line)
        headers = Headers(headers)
        if "set-cookie" in headers:
            cookie = headers["set-cookie"]
            h = makehost(host, port)
            if h not in jar:
                jar.add_domain(h)
            domain = jar[h][0]
            if isinstance(cookie, list):
                for c in cookie:
                    domain.add_cookie(c)
            else:
                domain.add_cookie(cookie)
        body = b""
        chunked = headers.get("transfer-encoding", "").strip() == "chunked"
        if not chunked:
            cl = int(headers.get("content-length", -1))
            if cl == -1:
                warnings.warn(
                    "no content-length nor transfer-encoding, setting socket timeout"
                )
                sock.settimeout(0.5)
                while True:
                    try:
                        b = file.read(1)  # recv 1 byte
                        if not b:
                            break
                    except socket.timeout:  # end of response??
                        break
                    body += b
            else:
                body = file.read(cl)  # recv <content-length> bytes
        else:  # chunked read
            while True:
                chunksize = int(file.readline().strip(), base=16)  # get chunk size
                if chunksize == 0:  # final byte
                    break
                chunk = file.read(chunksize)
                file.read(2)  # discard CLRF
                body += chunk
    except:
        del pool[host, port]
        raise
    end_time = time.time()
    elapsed_time = end_time - start_time
    content_encoding = headers.get("content-encoding", "identity")
    decoded_body = decode_content(body, content_encoding)

    return Response(
        status, headers, decoded_body, history, url, False, body, elapsed_time
    )


def set_debug(d=True):
    builtins.debug = d


def absolute_path(url, last_url, scheme, host):
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
    method="GET",
    headers={},
    body=b"",
    auth=(),
    redirlimit=20,
    content_type=None,
    timeout=30,
    history=None,
    debug=False,
):
    """
    Performs request.

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
    :param debug: whether or not shall debug mode be used , defaults to ``False``
    :type debug: ``bool``
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
    resp = _raw_request(
        host,
        port,
        "/" + path,
        scheme,
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
    )
    if 300 <= resp.status < 400:

        if len(history) == redirlimit:
            debugger.warn("too many redirects!")
            raise TooManyRedirectsError("too many redirects")
        if "Location" in resp.headers:

            return request(
                absolute_path(
                    resp.headers["Location"], url, scheme, makehost(host, port)
                ),
                auth=auth,
                redirlimit=redirlimit,
                timeout=timeout,
                body=body,
                headers=headers,
                content_type=content_type,
                history=resp.history,
                debug=debug,
            )
    if resp.status == 401:
        if last_status == 401:
            debugger.warn("Invalid credentials!")
            return resp
        return request(
            url,
            auth=auth,
            redirlimit=redirlimit,
            timeout=timeout,
            body=body,
            headers=headers,
            content_type=content_type,
            history=resp.history,
            debug=debug,
        )
    if 399 < resp.status < 500:
        debugger.warn(f"Client error : {resp.status} {resp.reason}")
    if 499 < resp.status < 600:
        debugger.warn(f"Server error : {resp.status} {resp.reason}")
    if resp.ok:
        debugger.ok(f"Response OK")
    return resp


encodings = {
    "identity": lambda x: x,
    "deflate": _zlib_decompress,
    "gzip": _gzip_decompress,
}
jar = CookieJar()
cache = Cache()
nonce_counter = NonceCounter()
debugger = _Debugger(False)
pool = ConnectionPool()
__version__ = VERSION
__author__ = "Adam Jenca"
