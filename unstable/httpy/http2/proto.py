import itertools
from . import frame
from httpy.status import status_from_int
from httpy.utils import CaseInsensitiveDict

CONNECTION_SPECIFIC = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "host",
]


def serialize_data(data, max_frame_size):
    to_serialize = memoryview(data)
    frames = []
    while to_serialize:
        frames.append(
            frame.DataFrame(
                to_serialize[:max_frame_size].tobytes(),
                end_stream=len(to_serialize <= max_frame_size),
            )
        )
        to_serialize = to_serialize[max_frame_size:]
    return frames


def serialize_headers(headers, connection, end_stream, max_frame_size):
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
        self.headers = headers
        super().__init__(headers)


class HTTP2Sender:
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
    def __call__(self, connection, streamid, *_, **__):
        headers = {}
        body = b""
        stream = connection.streams[streamid]
        connection.debugger.info(f"Listening on {streamid}")
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            # next_frame.decode_headers(connection.hpack)
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                connection.debuger.ok("Response fully received (no body)")
                return int(headers[":status"]), headers, b"", b""
            if next_frame.end_headers:
                break
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.DataFrame], enable_closed=True
            )
            body += next_frame.data
            if next_frame.end_stream:
                connection.debugger.ok("Response fully received (with body)")
                return (
                    status_from_int(int(headers[":status"])),
                    HTTP2Headers(headers),
                    body,
                    body,
                )
