from httpy import ProtoVersion
import itertools
from . import frame


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
    to_serialize = memoryview(connection.client_hpack.encode_headers(headers))
    print(headers,to_serialize)
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


class HTTP2Sender:
    def __init__(self, method, headers, body, path, authority, connection, **_):
        self.method = method
        self.path = path
        self.authority = authority
        self.body = body
        self.headers = headers
        self.connection = connection
        self.stream = None
        self.headers.update(
            {
                ":path": path,
                ":method": method,
                ":authority": authority,
                ":scheme": "https",
            }
        )
        self.data_frames = serialize_data(
            body, connection.settings.server_settings["max_frame_size"]
        )
        self.header_frames = serialize_headers(
            self.headers,
            connection,
            not body,
            connection.settings.server_settings["max_frame_size"],
        )
        print([x.__dict__ for x in self.header_frames])
    def send(self):
        """Creates a new stream and sends the frames to it"""
        self.stream = self.connection.create_stream()
        for frm in itertools.chain(self.header_frames, self.data_frames):
            self.stream.send_frame(frm)
        return self.stream.streamid


class HTTP2Recver:
    def __call__(self, connection, streamid, **_):
        headers = {}
        body = b""
        stream = connection.streams[streamid]
        print("RCV",stream)
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.HeadersFrame, frame.ContinuationFrame],
                enable_closed=True,
            )
            print(next_frame,next_frame.__dict__)
            #next_frame.decode_headers(connection.hpack)
            headers.update(next_frame.decoded_headers)
            if next_frame.end_stream:
                return int(headers[":status"]), headers, b"", b""
            if next_frame.end_headers:
                break
        while True:
            next_frame = stream.recv_frame(
                frame_filter=[frame.DataFrame], enable_closed=True
            )
            body += next_frame.data
            if next_frame.end_stream:
                return int(headers[":status"]), headers, body, body
