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
    def __init__(self, streamid, conn):
        self.streamid = streamid
        self.conn = conn
        self.state = StreamState.IDLE
        self.framequeue = queue.Queue()
    def recv_frame(self, f):
        frame=self.framequeue.get()
        err = None
        if self.state == StreamState.IDLE:
            if f.frame_type != frame.HTTP2_FRAME_PRIORITY:
                err = 
                
    def __eq__(self,s):
        return s.streamid==self.streamid
    def send_frame(self, f):
        errmsg = None
        ## BLOCK: State changes
        if self.state == StreamState.IDLE:
            if f.frame_type == frame.HTTP2_FRAME_HEADERS:
                if f.flags & 0x1:  # end stream
                    self.state = StreamState.HALF_CLOSED_LOCAL
                else:
                    self.state = StreamState.OPEN
            elif f.frame_type == frame.HTTP2_FRAME_PUSH_PROMISE:
                self.state = StreamState.RESERVED_LOCAL
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
