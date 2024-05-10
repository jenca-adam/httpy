import gzip, zlib, io, struct, ctypes, socket, struct, os

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
    "mk_header",
    "_extract_sslobj",
    "mkdict",
    "urlencode",
    "_generate_boundary",
    "get_content_type",
    "_unpk_float",
    "multipart",
    "encode_form_data",
    "determine_charset",
    "makehost",
    "reslash",
    "deslash",
    "generate_cnonce",
    "File",
    "_binappendstr",
    "_binappendfloat",
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


def mk_header(key_value_pair):
    """Makes header from key/value pair"""
    if isinstance(key_value_pair[1], list):
        header = ""
        for key_value in key_value_pair[1]:
            header += key_value_pair[0] + ": " + key_value + "\r\n"
        return header.strip()
    return ": ".join([force_string(key_value) for key_value in key_value_pair])


def read_until(fp, token):  # meant for bytes
    buf = []
    while True:
        nx = fp.read(1)
        if nx == token or not nx:
            break
        buf.append(nx)
    return b"".join(buf)


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


def _fix_multiple_values(q):
    if isinstance(q, dict):
        return q
    r = {}
    multiple = set()
    for k, v in q:
        if k in r:
            if k in multiple:
                r[k] += (v,)
            else:
                r[k] = (r[k], v)
                multiple.add(k)
        else:
            r[k] = v
    return r


def _make_case_insensitive(val):
    if isinstance(val, tuple):
        return tuple(map(_make_case_insensitive, val))
    elif isinstance(val, list):
        return list(map(_make_case_insensitive, val))
    elif isinstance(val, str):
        return CaseInsensitiveString(val)
    return val


class CaseInsensitiveString(str):
    def __init__(self, st):
        self._stl = st.lower()
        self._string = st

    def __new__(cls, _string):
        return super().__new__(cls, _string)

    def __eq__(self, oth):
        try:
            return self._stl == oth.lower()
        except:
            return False


def _binappendstr(s):
    return struct.pack("!H", len(force_bytes(s))) + force_bytes(s)


def _binappendfloat(b):
    b = float(b)
    ba = struct.pack("f", b)
    return bytes([len(ba)]) + ba


def _mk_string(a):
    if isinstance(a, bytes):
        return a.decode()
    return a


class CaseInsensitiveDict(dict):
    """Case insensitive subclass of dictionary that supports multiple values for a single key"""

    def __init__(self, data):
        data = _fix_multiple_values(data)
        self.lowercase = {
            _mk_string(k).lower(): _make_case_insensitive(_mk_string(v))
            for k, v in data.items()
        }
        self.original = data
        super().__init__(self.original)

    def __contains__(self, item):
        return (_mk_string(item).lower() in self.lowercase) | (
            _mk_string(item) in self.original
        )

    def __getitem__(self, item):
        try:
            return self.lowercase[_mk_string(item).lower()]
        except KeyError:
            return self.original[_mk_string(item)]

    def __setitem__(self, item, v):
        val = _make_case_insensitive(v)
        self.lowercase[_mk_string(item).lower()] = val
        self.original[_find(item, self.original)] = val
        super().__init__(self.original)  # remake??

    def __delitem__(self, item):
        del self.lowercase[_mk_string(item).lower()]
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
    host, port = address
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


def _extract_sslobj(reader, writer):
    ### LMAO
    return writer.transport.get_extra_info("ssl_object")


def mkdict(kvp):
    """Makes dict from key/value pairs"""
    d = {}
    kvp = list(kvp)
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


def _generate_boundary():
    return (
        b"--"
        + "".join(random.choices(string.ascii_letters + string.digits, k=10)).encode()
        + b"\r\n"
    )


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


def multipart(form, boundary=None):
    """Builds multipart/form-data from form"""
    if boundary is None:
        boundary = generate_boundary()
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
    return url.rstrip("/")


def generate_cnonce(length=16):
    return hex(random.randrange(16**length))[2:]


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


encodings = {
    "identity": lambda x: x,
    "deflate": _zlib_decompress,
    "gzip": _gzip_decompress,
}
