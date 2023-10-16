import frame
import error
import stream


class FrameQueue:
    def __init__(self, streams, conn):
        self.streams = streams
        self.conn=conn
    def add_stream(self, s):
        self.streams.add_stream(s)
    def throw(self,err):
        for stream in self.streams:
            stream.framequeue.put(err)
    def process(self, f):
        if f.frame_type == frame.HTTP2_FRAME_HEADERS:
            f.decode_headers(self.conn.hpack)
        if f.streamid == 0:
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                error.throw(f)
            if f.frame_type == frame.HTTP2_FRAME_PING:
                return frame.PingFrame(f.data, ack=True)
        else:
            target_stream = self.streams[f.streamid]
            err, closed = target_stream.error_check(f)
            if err is not None:
                self.conn.close_on_error(err)
                raise err
            if f.frame_type in (
                frame.HTTP2_FRAME_GOAWAY,
                frame.HTTP2_FRAME_RST_STREAM,
            ):
                error.throw(f)
            else:
                target_stream.framequeue.put([f, closed])
