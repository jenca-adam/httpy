import json
import math

try:
    import chardet
except ModuleNotFoundError:
    chardet = None
from .utils import *  #
from .errors import ContentTypeError  #
from .status import Status  #
from .headers import Headers  #
from .cache import cache_write
from .common import HTTPY_DIR


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
    :param request: The Request object for this response
    :ivar request: The Request object for this response
    :type request: Request
    :type method: str
    :ivar method: Indicates HTTP method used to request
    :param original_content: Document content before any Content-Encoding was applied.
    :type original_content: bytes
    :param time_elapsed: Total request time
    :type time_elapsed: float
    :ivar ok: `self.status==200`
    """

    def __init__(
        self,
        method,
        status,
        headers,
        content,
        history,
        url,
        fromcache,
        original_content,
        request,
        time_elapsed=math.inf,
        cache=True,
        base_dir=HTTPY_DIR / "default",
    ):
        self.method = method
        self.status = status
        self.headers = headers
        self.content = content
        self.ok = self.status == 200
        self.reason = self.status.reason
        self._original = self.original_content = original_content
        try:
            self.speed = len(self._original) / time_elapsed
        except ZeroDivisionError:  # bug #28 permanent redirects
            self.speed = float("inf")
        self.url = reslash(url)
        self.fromcache = fromcache
        self._time_elapsed = time_elapsed
        self.content_type = (
            headers.get("content-type", "text/html").split(";")[0].strip()
        )  # remove charset suffix
        self._charset = determine_charset(headers)
        self.history = history
        self.request = request
        self.history.append(self)

        if (
            not self.fromcache
            and (self.content or self.headers or self.status)
            and cache
        ):
            cache_write(self, base_dir, expires_override=headers.get("Expires", None))

    @classmethod
    def cacheload(self, cache_file, request_class):
        """
        Loads response from CacheFile.

        :param cache_file: CacheFile to load from
        :type cache_file: CacheFile
        """
        return Response(
            cache_file.method,
            cache_file.status,
            cache_file.headers,
            cache_file.body,
            [],
            cache_file.url,
            True,
            cache_file.content,
            request_class(
                cache_file.url,
                cache_file.request_headers,
                cache_file.method,
                None,
                True,
                cache_file.http_version,
            ),
            cache_file.time_elapsed,
        )

    @property
    def string(self):
        if self.charset is None:
            return self.content.decode()
        return self.content.decode(self.charset)

    @classmethod
    def plain(self):
        return Response(
            "",
            Status(b"000"),
            Headers({}),
            b"",
            [],
            "",
            False,
            b"",
            None,
        )

    @property
    def charset(self):
        if self._charset is None and chardet is not None:
            self._charset = chardet.detect(self.content)["encoding"]
        return self._charset

    @property
    def json(self):
        if self.content_type == (
            "application/json"
        ):  # the ONLY acceptable MIME, see RFC 4627
            ## NOTE: What about the encoding suffix???
            ##   AJ: fixed! (2.0.0)
            if self._charset is None:
                JSON = self.content.decode("UTF-8")  #
            else:
                JSON = self.content.decode(self._charset)
            return json.loads(JSON)
        raise ContentTypeError(
            f"Content type is {self.content_type} , not application/json"
        )

    def __repr__(self):
        return f"<Response {self.method} [{self.status} {self.reason}] ({self.url})>"
