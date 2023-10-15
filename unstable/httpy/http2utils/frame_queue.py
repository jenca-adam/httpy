import queue
import frame
import error
import stream


class FrameQueue:
    def __init__(self, streams, conn):
        self.streams = streams

    def add_stream(self, stream):
        self.streams.add_stream(stream)

    def process(self, f):
        if f.streamid == 0:
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                throw(f)
            conn.framequeue.put(f)
        else:
            target_stream = self.streams[f.streamid]
            err, closed = target_stream.error_check(f)
            if err is not None:
                raise err
            if f.frame_type == frame.HTTP2_FRAME_PING:
                return frame.PingFrame(f.data, ack=True)
            elif f.frame_type in (
                frame.HTTP2_FRAME_GOAWAY,
                frame.HTTP2_FRAME_RST_STREAM,
            ):
                error.throw(f)
            else:
                target_stream.framequeue.put((f, closed))
