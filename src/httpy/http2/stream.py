import enum
import queue
import asyncio
from . import frame
from .error import *
from .window import Window


class StreamToken(enum.Enum):
    CLOSE_TOKEN = 0
    FRAME_TOKEN = 1
    ERROR_TOKEN = 2


class StreamState(enum.Enum):
    IDLE = 0
    RESERVED_LOCAL = 1
    RESERVED_REMOTE = 2
    OPEN = 3
    HALF_CLOSED_LOCAL = 4
    HALF_CLOSED_REMOTE = 5
    CLOSED = 6


class StreamEvent:
    def __init__(self, token, value):
        self.token = token
        self.value = value


class Stream:
    """
    A HTTP/2 synchronous stream implementation.
    """

    def __init__(self, streamid, conn, window_size, weight=0, dependency=0):
        self.streamid = streamid
        self.conn = conn
        self.weight = weight
        self.dependency = dependency
        self.state = StreamState.IDLE
        self.window = Window(window_size)
        self.outbound_window = conn.settings.server_settings["initial_window_size"]
        self.framequeue = queue.Queue()

    def error_check(self, f):
        """
        Checks a frame for stream state errors.
        """
        err = None
        if self.state == StreamState.IDLE:
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY received on an idle stream",
                    "@ Stream.recv_frame()",
                )
        elif (
            self.state == StreamState.RESERVED_LOCAL
        ):  # all this is likely not needed, keeping in case we ever decide to enable server push
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY or RST_STREAM received on an reserved(local) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.RESERVED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY or RST_STREAM received on an reserved(remote) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.OPEN:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            elif f.flags & 0x1:
                self.state = StreamState.HALF_CLOSED_REMOTE
        elif self.state == StreamState.HALF_CLOSED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            elif f.flags & 0x1:
                self.state = StreamState.CLOSED
        elif self.state == StreamState.HALF_CLOSED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                err = STREAM_CLOSED(
                    "Frame other than PRIORITY, WINDOW_UPDATE or RST_STREAM received on an reserved(remote) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.CLOSED:
            return None, True

        return err, False

    def recv_frame(self, enable_closed=False, frame_filter=None):
        """
        Returns the last frame received on this stream.
        """
        if not enable_closed and self.state == StreamState.CLOSED:
            raise Refuse("refusing to receive a frame on a closed stream")
        while self.framequeue.empty():
            self.conn.process_next_frame()
        n = self.framequeue.get()
        if n.token == StreamToken.CLOSE_TOKEN:
            self.state = StreamState.CLOSED
        elif n.token == StreamToken.ERROR_TOKEN:
            _, err, tb = n.value
            raise err.with_traceback(tb)
        if frame_filter is not None and (n.value.__class__ not in frame_filter):
            return self.recv_frame(enable_closed, frame_filter)
        return n.value

    def __eq__(self, s):
        return s.streamid == self.streamid

    def send_frame(self, f):
        """
        Sends a frame to the server on this stream.
        """
        errmsg = None
        ## BLOCK: State changes
        if self.state == StreamState.IDLE:
            if f.frame_type == frame.HTTP2_FRAME_HEADERS:
                if f.flags & 0x1:  # end stream
                    self.state = StreamState.HALF_CLOSED_LOCAL
                else:
                    self.state = StreamState.OPEN
            elif f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on an idle stream"

        elif self.state == StreamState.RESERVED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type == frame.HTTP2_FRAME_HEADERS:
                self.state = StreamState.HALF_CLOSED_REMOTE
            elif f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on a reserved(local) stream"
        elif self.state == StreamState.RESERVED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                errmsg = f"refusing to send a {f.__class__.__name__} on a reserved(remote) stream"
        elif self.state == StreamState.OPEN:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            if f.flags & 0x1:  # end_stream
                self.state = StreamState.HALF_CLOSED_LOCAL
        elif self.state == StreamState.HALF_CLOSED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                errmsg = f"refusing to send a {f.__class__.__name__} on a half-closed(local) stream"
        elif self.state == StreamState.HALF_CLOSED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM or f.flags & 0x1:
                self.state = StreamState.CLOSED
        elif self.state == StreamState.CLOSED:
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on a closed stream"
        if errmsg is not None:
            raise Refuse(errmsg)
        f.streamid = self.streamid
        self.conn.send_frame(f)


class AsyncStream:
    """
    Asynchronous HTTP/2 stream implementation
    For method description, see Stream.__doc__
    """

    def __init__(self, streamid, conn, window_size, weight=0, dependency=0):
        self.streamid = streamid
        self.conn = conn
        self.weight = weight
        self.dependency = dependency
        self.state = StreamState.IDLE
        self.window = Window(window_size)
        self.outbound_window = conn.settings.server_settings["initial_window_size"]
        self.framequeue = asyncio.Queue()

    async def error_check(self, f):
        err = None
        if self.state == StreamState.IDLE:
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY received on an idle stream",
                    "@ Stream.recv_frame()",
                )
        elif (
            self.state == StreamState.RESERVED_LOCAL
        ):  # all this is likely not needed, keeping in case we ever decide to enable server push
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY or RST_STREAM received on an reserved(local) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.RESERVED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = PROTOCOL_ERROR(
                    "Frame other than PRIORITY or RST_STREAM received on an reserved(remote) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.OPEN:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            elif f.flags & 0x1:
                self.state = StreamState.HALF_CLOSED_REMOTE
        elif self.state == StreamState.HALF_CLOSED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
                throw(f)
            elif f.flags & 0x1:
                self.state = StreamState.CLOSED
        elif self.state == StreamState.HALF_CLOSED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                err = STREAM_CLOSED(
                    "Frame other than PRIORITY, WINDOW_UPDATE or RST_STREAM received on an reserved(remote) stream",
                    "@ Stream.recv_frame()",
                )
        elif self.state == StreamState.CLOSED:
            return None, True

        return err, False

    async def recv_frame(self, enable_closed=False, frame_filter=None):
        if not enable_closed and self.state == StreamState.CLOSED:
            raise Refuse("refusing to receive a frame on a closed stream")
        while self.framequeue.empty():
            token = await asyncio.create_task(
                self.conn.process_next_frame(self.framequeue)
            )
            if token is not None:
                return token
        n = await self.framequeue.get()
        if n.token == StreamToken.CLOSE_TOKEN:
            self.state = StreamState.CLOSED
        elif n.token == StreamToken.ERROR_TOKEN:
            _, err, tb = n.value
            raise err.with_traceback(tb)
        if frame_filter is not None and (n.value.__class__ not in frame_filter):
            return await self.recv_frame(enable_closed, frame_filter)
        return n.value

    def __eq__(self, s):
        return s.streamid == self.streamid

    async def send_frame(self, f):
        errmsg = None
        ## BLOCK: State changes
        if self.state == StreamState.IDLE:
            if f.frame_type == frame.HTTP2_FRAME_HEADERS:
                if f.flags & 0x1:  # end stream
                    self.state = StreamState.HALF_CLOSED_LOCAL
                else:
                    self.state = StreamState.OPEN
            elif f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on an idle stream"

        elif self.state == StreamState.RESERVED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type == frame.HTTP2_FRAME_HEADERS:
                self.state = StreamState.HALF_CLOSED_REMOTE
            elif f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on a reserved(local) stream"
        elif self.state == StreamState.RESERVED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                errmsg = f"refusing to send a {f.__class__.__name__} on a reserved(remote) stream"
        elif self.state == StreamState.OPEN:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            if f.flags & 0x1:  # end_stream
                self.state = StreamState.HALF_CLOSED_LOCAL
        elif self.state == StreamState.HALF_CLOSED_LOCAL:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM:
                self.state = StreamState.CLOSED
            elif f.frame_type not in (
                frame.HTTP2_FRAME_PRIORITY,
                frame.HTTP2_FRAME_WINDOW_UPDATE,
            ):
                errmsg = f"refusing to send a {f.__class__.__name__} on a half-closed(local) stream"
        elif self.state == StreamState.HALF_CLOSED_REMOTE:
            if f.frame_type == frame.HTTP2_FRAME_RST_STREAM or f.flags & 0x1:
                self.state = StreamState.CLOSED
        elif self.state == StreamState.CLOSED:
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                errmsg = f"refusing to send a {f.__class__.__name__} on a closed stream"
        if errmsg is not None:
            raise Refuse(errmsg)
        f.streamid = self.streamid
        await self.conn.send_frame(f)
