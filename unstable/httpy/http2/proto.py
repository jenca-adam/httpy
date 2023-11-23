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
    to_serialize = memoryview(connection.hpack.encode_headers(headers))
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
    def __init__(self, method, headers, body, path, authority, connection):
        self.method = method
        self.path = path
        self.authority = authority
        self.body = body
        self.headers = headers
        self.connection = connection
        self.stream = None
        self.headers.update(
            {":path": path, ":method": method, ":authority": authority}
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
    def send(self):
        """Creates a new stream and sends the frames to it"""
        self.stream = self.connection.create_stream()
        for frm in in itertools.chain(self.header_frames,self.data_frames):
            self.stream.send_frame(frm)
        return self.stream
