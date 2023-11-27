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
