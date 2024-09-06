from .utils import mk_header, decode_content
from .headers import Headers
from .debugger import _debugprint
from .status import Status
from .stream import Stream, AsyncStream
from .cache import cache_write
from . import http2
import warnings
import socket


def _read_one_chunk(file):
    chunksize = int(file.readline().strip(), base=16)  # get chunk size
    if chunksize == 0:  # final byte
        return
    chunk = file.read(chunksize)
    file.readline()  # discard CLRF (but be more permissive)
    return chunk


def _read_chunked(file):
    body = []
    while True:
        next_chunk = _read_one_chunk(file)
        if next_chunk is None:
            break
        body.append(next_chunk)
    return b"".join(body)


class ProtoVersion:
    def send_request(self, sock, *args):
        _senderobj = self.sender(*args)
        return _senderobj.send(sock)

    def recv_response(self, sock, *args):
        _recverobj = self.recver(sock, *args)
        _recverobj.load_headers()
        _recverobj.load_body()
        return (
            _recverobj._status,
            _recverobj._headers,
            _recverobj._decoded_body,
            _recverobj.body,
        )

    ### GENERATOR

    def _stream_response(self, sock, *args):
        _recverobj = self.recver(sock, *args)
        _recverobj.load_headers()
        yield _recverobj  # FIRST PASS - internal (don't return the stream object unless the response is OK)
        yield _recverobj._status, _recverobj._headers, _recverobj  # SECOND PASS - stream class (set attributes)
        while True:
            yield _recverobj.stream(), _recverobj
            if _recverobj.finished:
                return

    def stream_response(self, sock, *args):
        _gen = self._stream_response(sock, *args)
        _recver = next(_gen)
        if _recver._status == 200:
            return Stream(_gen)
        _recver.load_body()  # Just return a response if it's not 200
        return (_recver._status, _recver._headers, _recver._decoded_body, _recver.body)


class AsyncProtoVersion:
    async def send_request(self, sock, *args):
        _senderobj = self.sender(*args)
        return await _senderobj.send(sock)

    async def recv_response(self, sock, *args):
        _recverobj = self.recver(sock, *args)
        await _recverobj.load_headers()
        await _recverobj.load_body()
        return (
            _recverobj._status,
            _recverobj._headers,
            _recverobj._decoded_body,
            _recverobj.body,
        )

    ### GENERATOR

    async def _stream_response(self, sock, *args):
        _recverobj = self.recver(sock, *args)
        await _recverobj.load_headers()

        yield _recverobj  # FIRST PASS - internal (don't return the stream object unless the response is OK)

        yield _recverobj._status, _recverobj._headers, _recverobj

        while True:
            next_chunk = await _recverobj.stream()
            yield next_chunk, _recverobj
            if _recverobj.finished:
                return

    async def stream_response(self, sock, *args):
        _agen = self._stream_response(sock, *args)
        _recver = await anext(_agen)
        if _recver._status == 200:
            return AsyncStream(_agen)
        await _recver.load_body()  # Just return a response if it's not 200
        return (_recver._status, _recver._headers, _recver._decoded_body, _recver.body)


class HTTP11Sender:
    def __init__(self, method, headers, body, path, debug):
        self.method = method
        self.headers = headers
        self.body = body
        self.path = path
        self.debug = debug
        headers = "\r\n".join([mk_header(i) for i in self.headers.items()])
        request_data = f"{method} {path} HTTP/1.1" + "\r\n"
        request_data += headers
        request_data += "\r\n\r\n"
        self.request_data = request_data

    def send(self, sock):
        _debugprint(self.debug, "\nsend:\n" + self.request_data)
        sock.send(self.request_data.encode())
        if self.body:
            sock.send(self.body)


class HTTP11Recver:
    def __init__(self, sock, debug, timeout):
        self.sock = sock
        self.debug = debug
        self.timeout = timeout
        self.__joined_body = None
        self._headers = None
        self._body = []
        self._decoded_body = None
        self._status = None
        self._chunked = False
        self.bytes_read = 0
        self.finished = False
        self.file = sock.makefile("b")

    def load_headers(self):
        statusline = self.file.readline()
        _debugprint(self.debug, "\nresponse: ")
        _debugprint(self.debug, statusline)
        if not statusline:
            debugger.warn("dead connection")
            raise DeadConnectionError("peer did not send a response")
        self._status = Status(statusline)
        headers = []
        while True:
            line = self.file.readline()
            if not line.strip(b"\r\n"):
                break
            _debugprint(self.debug, line.decode(), end="")
            headers.append(line)
        self._headers = Headers(headers)
        self._chunked = (
            self._headers.get("transfer-encoding", "").strip().lower() == "chunked"
        )
        if not self._chunked and "content-length" not in self._headers:
            warnings.warn(
                "no content-length nor transfer-encoding, setting socket timeout"
            )
            self.sock.settimeout(0.5)

        return self._headers

    def load_body(self):
        if not self._chunked:
            cl = int(self._headers.get("content-length", -1))
            if cl == -1:
                try:
                    body = []
                    while True:
                        try:
                            b = self.file.read(1)  # recv 1 byte
                            if not b:
                                break
                        except socket.timeout:  # end of response??
                            break
                        body.append(b)
                    self._body = body
                finally:
                    self.sock.settimeout(self.timeout)
            else:
                self._body = [self.file.read(cl)]  # recv <content-length> bytes
        else:  # chunked read
            self._body = [_read_chunked(self.file)]
        content_encoding = self._headers.get("content-encoding", "identity")
        self._decoded_body = decode_content(self.body, content_encoding)

    @property
    def body(self):
        if self.__joined_body is not None and self.finished:
            return self.__joined_body
        self.__joined_body = b"".join(self._body)
        return self.__joined_body

    def stream(self):
        if self._chunked:
            next_chunk = _read_one_chunk(self.file)
            if not next_chunk:
                self.finished = True
                return
            self.bytes_read += len(next_chunk)
            self._body.append(next_chunk)
            return next_chunk
        else:
            if "content-length" not in self._headers:
                try:
                    next_byte = self.file.read(1)
                    self._body.append(next_byte)
                    self._bytes_read += 1
                except socket.timeout:
                    next_byte = None
                if not next_byte:
                    self.sock.settimeout(self.timeout)
                    return None
                return next_byte
            if self.bytes_read == int(self._headers["content-length"]):
                return None
            next_byte = self.file.read(1)
            if not next_byte:
                return None
            self._body.append(next_byte)
            self.bytes_read += 1
            return next_byte


class HTTP11(ProtoVersion):
    """
    A sender/receiver for HTTP/1.1 requests
    """

    version = "1.1"
    sender = HTTP11Sender
    recver = HTTP11Recver


class HTTP2(ProtoVersion):
    """
    A sender/receiver for synchronous HTTP/2 requests
    """

    version = "2"
    sender = http2.proto.HTTP2Sender
    recver = http2.proto.HTTP2Recver


class _HTTP2Async(AsyncProtoVersion):
    """
    A sender/receiver for asynchronous HTTP/2 requests
    """

    version = "2"
    sender = http2.proto.AsyncHTTP2Sender
    recver = http2.proto.AsyncHTTP2Recver
