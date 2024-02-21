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

    def __call__(self, connection, streamid, *_, **__):
        """
        Receives a response on a stream with a given ID.
        """
        headers = {}
        body = b""
        stream = connection.streams[streamid]
        connection.debugger.info(f"Listening on {streamid}")
        connection.debugger.debugprint("recv:")
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            # next_frame.decode_headers(connection.hpack)
            connection.debugger.debugprint(
                "\n".join(mk_header(kvp) for kvp in next_frame.decoded_headers.items())
            )
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                connection.debugger.ok("Response fully received (no body)")
                return (
                    status_from_int(headers[":status"]),
                    HTTP2Headers(headers),
                    b"",
                    b"",
                )
            if next_frame.end_headers:
                break
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.DataFrame], enable_closed=True
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            body += next_frame.data
            if next_frame.end_stream:
                connection.debugger.ok("Response fully received (with body)")
                break
        headers_object = HTTP2Headers(headers)
        content_encoding = headers_object.get("content-encoding", "identity")
        decoded_body = decode_content(body, content_encoding)

        return status_from_int(headers[":status"]), headers_object, decoded_body, body


class AsyncHTTP2Sender:
    """
    Asynchronous HTTP/2 sender implementation.
    For method details, see HTTP2Sender.__doc__
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
    Asynchronous HTTP/2 receiver implementation.
    For method details, see HTTP2Recver.__doc__
    """

    async def __call__(self, connection, streamid, *_, **__):
        headers = {}
        body = b""
        stream = connection.streams[streamid]
        connection.debugger.info(f"Listening on {streamid}")
        while True:
            next_frame = await stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            # next_frame.decode_headers(connection.hpack)
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                connection.debuger.ok("Response fully received (no body)")
                return (
                    status_from_int(headers[":status"]),
                    HTTP2Headers(headers),
                    b"",
                    b"",
                )
            if next_frame.end_headers:
                break
        while True:
            next_frame = await stream.recv_frame(
                frame_filter=[frame.DataFrame], enable_closed=True
            )
            if next_frame == frame.ConnectionToken.CONNECTION_CLOSE:
                raise ConnectionClosedError
            body += next_frame.data
            if next_frame.end_stream:
                connection.debugger.ok("Response fully received (with body)")
                break
        headers_object = HTTP2Headers(headers)
        content_encoding = headers_object.get("content-encoding", "identity")
        decoded_body = decode_content(body, content_encoding)

        return status_from_int(headers[":status"]), headers_object, decoded_body, body
