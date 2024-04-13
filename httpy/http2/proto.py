import itertools
from . import frame
from httpy.status import status_from_int
from httpy.utils import CaseInsensitiveDict, decode_content, mk_header
from httpy.errors import ConnectionClosedError

CONNECTION_SPECIFIC = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "host",
]


def serialize_data(data, max_frame_size):
    """
    Serialises data as a sequence of DATA frames
    """
    to_serialize = memoryview(data)
    frames = []
    while to_serialize:
        frames.append(
            frame.DataFrame(
                to_serialize[:max_frame_size].tobytes(),
                end_stream=len(to_serialize) <= max_frame_size,
            )
        )
        to_serialize = to_serialize[max_frame_size:]
    return frames


def serialize_headers(headers, connection, end_stream, max_frame_size):
    """
    Serialises headers as a sequence of HEADERS/CONTINUATION frames
    """
    to_serialize = memoryview(
        connection.client_hpack.encode_headers(
            filter((lambda x: x[0].lower() not in CONNECTION_SPECIFIC), headers.items())
        )
    )  # skip connection-specific headers DON'T THROW AN ERROR
    # to_serialize = memoryview(connection.client_hpack.encode_headers(headers))
    end_headers = len(to_serialize) <= max_frame_size
    frames = [
        frame.HeadersFrame(
            to_serialize[:max_frame_size].tobytes(),
            end_headers=end_headers,
            end_stream=end_stream and end_headers,
        )
    ]
    to_serialize = to_serialize[max_frame_size:]
    while to_serialize:
        end_headers = len(to_serialize) <= max_frame_size
        frames.append(
            frame.ContinuationFrame(
                to_serialize[:max_frame_size].tobytes(),
                end_headers=end_stream,
                end_stream=end_stream and end_headers,
            )
        )
        to_serialize = to_serialize[max_frame_size:]
    return frames


class HTTP2Headers(CaseInsensitiveDict):
    def __init__(self, headers):
        self.headers = dict(filter(lambda x: not x[0].startswith(":"), headers.items()))
        super().__init__(headers)


class HTTP2Sender:
    """
    A synchronous HTTP/2 sender.
    """

    def __init__(self, method, headers, body, path, debugger, authority=None, *_, **__):
        self.method = method
        self.debugger = debugger
        self.path = path

        self.authority = authority or headers.get("Host", headers.get("host"))
        self.body = body
        self.headers = headers
        self.headers.update(
            {
                ":path": path,
                ":method": method,
                ":authority": self.authority,
                ":scheme": "https",
            }
        )

    def send(self, connection):
        """Creates a new stream and sends the frames to it"""
        self.debugger.debugprint("send:")
        self.debugger.debugprint(
            "\n".join(mk_header(kvp) for kvp in self.headers.items())
        )
        self.data_frames = serialize_data(
            self.body, connection.settings.server_settings["max_frame_size"]
        )
        self.header_frames = serialize_headers(
            self.headers,
            connection,
            not self.body,
            connection.settings.server_settings["max_frame_size"],
        )

        stream = connection.create_stream()
        for frm in itertools.chain(self.header_frames, self.data_frames):
            stream.send_frame(frm)
        return stream.streamid


class HTTP2Recver:
    """
    A synchronous HTTP/2 receiver implementation.
    """

    def __init__(self, connection, streamid, *_, **__):
        self.connection = connection
        self.streamid = streamid
        self._status = None
        self._headers = None
        self._body = []
        self.__joined_body = None
        self.finished = False
        self.bytes_read = 0
        self._decoded_body = None
        self._has_body = True

    def load_headers(self, *_, **__):
        """
        Loads the headers for a response
        """
        headers = {}
        self._stream = self.connection.streams[self.streamid]
        self.connection.debugger.info(f"Listening on {self.streamid}")
        self.connection.debugger.debugprint("recv:")
        while True:
            next_frame = self._stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            # next_frame.decode_headers(connection.hpack)
            self.connection.debugger.debugprint(
                "\n".join(mk_header(kvp) for kvp in next_frame.decoded_headers.items())
            )
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                self.connection.debugger.ok("Response fully received (no body)")
                self._has_body = False
                break  # Just in case
            if next_frame.end_headers:
                break
        self._headers = HTTP2Headers(headers)
        self._status = status_from_int(headers[":status"])

    def load_body(self):
        """Loads the response body"""
        self._body = []
        if (
            self._has_body
        ):  # BUGFIX: http2 receiver hanging after a response with no body was received
            while True:
                next_frame = self._stream.recv_frame(
                    frame_filter=[frame.DataFrame], enable_closed=True
                )
                if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                    raise ConnectionClosedError
                self._body.append(next_frame.data)
                self.bytes_read += next_frame.payload_length
                if next_frame.end_stream:
                    self.connection.debugger.ok("Response fully received (with body)")
                    break
        self.finished = True
        content_encoding = self._headers.get("content-encoding", "identity")
        self._decoded_body = decode_content(self.body, content_encoding)

    @property
    def body(self):
        if self.__joined_body is not None and self.finished:
            return self.__joined_body
        self.__joined_body = b"".join(self._body)
        return self.__joined_body

    def stream(self):
        next_frame = self._stream.recv_frame(
            frame_filter=[frame.DataFrame], enable_closed=True
        )
        if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
            raise ConnectionClosedError
        self._body.append(next_frame.data)
        self.bytes_read += next_frame.payload_length
        if next_frame.end_stream:
            self.finished = True
        return next_frame.data


class AsyncHTTP2Sender:
    """
    An asynchronous HTTP/2 sender.
    """

    def __init__(self, method, headers, body, path, debugger, authority=None, *_, **__):
        self.method = method
        self.debugger = debugger
        self.path = path

        self.authority = authority or headers.get("Host", headers.get("host"))
        self.body = body
        self.headers = headers
        self.headers.update(
            {
                ":path": path,
                ":method": method,
                ":authority": self.authority,
                ":scheme": "https",
            }
        )

    async def send(self, connection):
        """Creates a new stream and sends the frames to it"""
        self.debugger.debugprint("send:")
        self.debugger.debugprint(
            "\n".join(mk_header(kvp) for kvp in self.headers.items())
        )
        self.data_frames = serialize_data(
            self.body, connection.settings.server_settings["max_frame_size"]
        )
        self.header_frames = serialize_headers(
            self.headers,
            connection,
            not self.body,
            connection.settings.server_settings["max_frame_size"],
        )

        stream = connection.create_stream()
        for frm in itertools.chain(self.header_frames, self.data_frames):
            await stream.send_frame(frm)
        return stream.streamid


class AsyncHTTP2Recver:
    """
    An  asynchronous HTTP/2 receiver implementation.
    """

    def __init__(self, connection, streamid, *_, **__):
        self.connection = connection
        self.streamid = streamid
        self._status = None
        self._headers = None
        self._body = []
        self.__joined_body = None
        self.finished = False
        self.bytes_read = 0
        self._decoded_body = None

    async def load_headers(self, *_, **__):
        """
        Loads the headers for a response
        """
        headers = {}
        self._stream = self.connection.streams[self.streamid]
        self.connection.debugger.info(f"Listening on {self.streamid}")
        self.connection.debugger.debugprint("recv:")
        while True:
            next_frame = await self._stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            # next_frame.decode_headers(connection.hpack)
            self.connection.debugger.debugprint(
                "\n".join(mk_header(kvp) for kvp in next_frame.decoded_headers.items())
            )
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                self.connection.debugger.ok("Response fully received (no body)")
            if next_frame.end_headers:
                break
        self._headers = HTTP2Headers(headers)
        self._status = status_from_int(headers[":status"])

    async def load_body(self):
        """Loads the response body"""
        self._body = []
        while True:
            next_frame = await self._stream.recv_frame(
                frame_filter=[frame.DataFrame], enable_closed=True
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            self._body.append(next_frame.data)
            self.bytes_read += next_frame.payload_length
            if next_frame.end_stream:
                self.connection.debugger.ok("Response fully received (with body)")
                break
        self.finished = True
        content_encoding = self._headers.get("content-encoding", "identity")
        self._decoded_body = decode_content(self.body, content_encoding)

    async def stream(self):
        next_frame = await self._stream.recv_frame(
            frame_filter=[frame.DataFrame], enable_closed=True
        )
        if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
            raise ConnectionClosedError
        self._body.append(next_frame.data)
        self.bytes_read += next_frame.payload_length
        if next_frame.end_stream:
            self.finished = True
        return next_frame.data

    @property
    def body(self):
        if self.__joined_body is not None and self.finished:
            return self.__joined_body
        self.__joined_body = b"".join(self._body)
        return self.__joined_body
