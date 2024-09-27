from .utils import mkdict, CaseInsensitiveDict, force_string


class Headers(CaseInsensitiveDict):
    """Class for HTTP headers"""

    def __init__(self, h):
        h = filter(None, h)
        _headers = mkdict(
            (
                force_string(a).split(":", 1)[0].strip().lower(),
                force_string(a).split(":", 1)[1].strip(),
            )
            for a in h
        )
        self.headers = {
            k: v
            for k, v in filter(lambda h: not h[0].startswith(":"), _headers.items())
        }
        self.h2_headers = {
            k: v for k, v in filter(lambda h: h[0].startswith(":"), _headers.items())
        }

        super().__init__(self.headers)

    def __setitem__(self, item, value):
        raise NotImplementedError
