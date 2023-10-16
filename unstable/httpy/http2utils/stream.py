import enum
import queue
import frame
from error import *


class StreamState(enum.Enum):
    IDLE = 0
    RESERVED_LOCAL = 1
    RESERVED_REMOTE = 2
    OPEN = 3
    HALF_CLOSED_LOCAL = 4
    HALF_CLOSED_REMOTE = 5
    CLOSED = 6


class Stream:
    def __init__(self, streamid, conn, weight=0, dependency=0):
        self.streamid = streamid
        self.conn = conn
        self.weight = weight
        self.dependency = dependency
        self.state = StreamState.IDLE
        self.framequeue = queue.Queue()

    def _recv_priority_frame(self, f):
        self.weight = f.priority_weight
        self.dependency = f.stream_dependency

    def set_priority(self, weight=None, dep=None):
        if weight is None and dep is None:
            return
        weight = weight or self.weight
        if p > 256:
            raise Refuse("refusing to set priority weight to an int over 256")
        d = d or self.dependency
        self.weight = p
        self.dependency = d
        self.send_frame(frame.PriorityFrame(self.dependency, self.weight))

    def error_check(self, f):
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

    def recv_frame(self):
        n = self.framequeue.get()
        if isinstance(n,tuple):
            print(n)
            _,err,tb = n
            raise err.with_traceback(tb)
        return n
    def __eq__(self, s):
        return s.streamid == self.streamid

    def send_frame(self, f):
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
