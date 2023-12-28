class HTTPyError(Exception):
    """A metaclass for all HTTPy Exceptions."""


class ContentTypeError(HTTPyError):
    """Raised if content type of resource does not match  the desired operation"""


class StatusError(HTTPyError):
    """Metaclass for ClientError and Server Error"""


class AuthError(HTTPyError):
    """Error in authentication"""


class DeadConnectionError(HTTPyError, ConnectionError):
    """Raised if the server didn't respond to the request"""


class ConnectionClosedError(HTTPyError, ConnectionError):
    """Connection Closed"""


class ConnectionLimitError(HTTPyError, ConnectionError):
    """Connection Limit reached"""


class ConnectionExpiredError(HTTPyError, ConnectionError, TimeoutError):
    """Connection Expired"""


class ServerError(StatusError):
    """Raised if server is not found or if it responded with 5xx code"""


class TooManyRedirectsError(HTTPyError):
    """Raised if server  responded with too many redirects (over redirection limit)"""


class ClientError(StatusError):
    """Raised if server responded with 4xx status code"""


class WebSocketError(HTTPyError):
    """Metaclass for exceptions in websockets"""


class WebSocketHandshakeError(WebSocketError):
    """Raised upon a failed handshake"""


class WebSocketClientError(WebSocketError):
    """Raised on erroneous close code"""


class OldCacheFileWarning(UserWarning):
    """Raised when the cache file has an old version"""
