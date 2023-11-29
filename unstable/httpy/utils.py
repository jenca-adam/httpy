import gzip, zlib, io


def force_string(anything):
    """Converts string or bytes to string"""
    try:
        if isinstance(anything, str):
            return anything
        if isinstance(anything, bytes):
            return anything.decode()
    except Exception:
        debugger.warn(f"Could not decode {anything}")
        raise
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
