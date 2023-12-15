import gzip, zlib, io, struct, ctypes, socket
from .patterns import URLPATTERN
from .errors import *
import math
__all__ = [
    "_mk2l",
    "get_host",
    "capitalize",
    "byte_length",
    "mkbits",
    "int2bytes",
    "getbytes",
    "_int16unpk",
    "mask",
    "force_string",
    "force_bytes",
    "_find",
    "CaseInsensitiveDict",
    "decode_content",
    "read_until",
]


def is_closed(connection):
    sock = (connection.is_http2 and connection._sock.sock) or (
        not connection.is_http2 and connection._sock
    )  # ugly trick
    if isinstance(sock, tuple):  # async
        _, writer = sock
        return writer.is_closing()
    return sock.fileno() == -1


def _mk2l(original):
    if len(original) == 1:
        original.append(True)
    return original

def read_until(fp,token):# meant for bytes
    buf=[]
    while True:
        nx = fp.read(1)
        if nx==token or not nx:
            break
        buf.append(nx)
    return b''.join(buf)

def get_host(url):
    return URLPATTERN.search(url).group("host")


def capitalize(string):
    return string[0].upper() + string[1:]


def byte_length(i):
    if i == 0:
        return 1
    return math.ceil(i.bit_length() / 8)


def mkbits(i, pad=None):
    j = bin(i)[2:]
    if pad is None:
        return j
    return "0" * (pad - len(j)) + j


def int2bytes(i, bl=None):
    if bl is None:
        bl = byte_length(i)
    return i.to_bytes(bl, "big")


def getbytes(bits):
    return int2bytes(int(bits, 2))


def _int16unpk(b):
    return struct.unpack("!H", b)[0]


def mask(data, mask):
    r = bytearray()
    for ix, i in enumerate(data):
        b = mask[ix % len(mask)]
        r.append(b ^ i)
    return r


def force_string(anything):
    """Converts string or bytes to string"""
    if isinstance(anything, str):
        return anything
    if isinstance(anything, bytes):
        return anything.decode()
    return str(anything)


def force_bytes(anything):
    """Converts bytes or string to bytes"""
    if isinstance(anything, bytes):
        return anything
    if isinstance(anything, str):
        return anything.encode()
    if isinstance(anything, int):
        return force_bytes(str(anything))
    if isinstance(anything, list):
        return force_bytes(anything[0])
    return bytes(anything)


def _find(key, d):
    for i in d:
        if i.lower() == key.lower():
            return i
    return key


class CaseInsensitiveDict(dict):
    """Case insensitive subclass of dictionary"""

    def __init__(self, data):
        self.lowercase = {force_string(k).lower(): v for k, v in dict(data).items()}
        self.original = data
        super().__init__(self.original)

    def __contains__(self, item):
        return (force_string(item).lower() in self.lowercase) | (
            force_string(item) in self.original
        )

    def __getitem__(self, item):
        try:
            return self.lowercase[force_string(item).lower()]
        except KeyError:
            return self.original[force_string(item)]

    def __setitem__(self, item, val):
        self.lowercase[force_string(item).lower()] = val
        self.original[_find(item, self.original)] = val
        super().__init__(self.original)  # remake??

    def __delitem__(self, item):
        del self.lowercase[force_string(item).lower()]
        del self.original[_find(item, self.original)]

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    def update(self, d):
        for key in d:
            self[key] = d[key]

    def __iter__(self):
        return iter(self.original)

    def keys(self):
        return self.original.keys()

    def values(self):
        return self.original.values()

    def items(self):
        return self.original.items()


def _create_connection_and_handle_errors(address):
    try:
        return socket.create_connection(address)
    except socket.gaierror as gai:
        # Get errno using ctypes, check for  -2(-3)
        if hasattr(ctypes, "pythonapi"):
            # Not PyPy

            errno = ctypes.c_int.in_dll(ctypes.pythonapi, "errno").value

        else:
            # PyPy
            errno = -72
            if str(gai).startswith("[Errno -2]") or str(gai).startswith("[Errno -3]"):
                errno = 2
        if errno in [2, 3]:
            raise ServerError(f"could not find server {host!r}")

        raise  # Added in 1.1.1


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
        raise
        return content


def _gzip_decompress(data):
    return gzip.GzipFile(fileobj=io.BytesIO(data)).read()


def _zlib_decompress(data):
    return zlib.decompress(data, -zlib.MAX_WBITS)


encodings = {
    "identity": lambda x: x,
    "deflate": _zlib_decompress,
    "gzip": _gzip_decompress,
}
