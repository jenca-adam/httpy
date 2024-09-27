from . import stream, frame, error
import asyncio


class FrameQueue:
    def __init__(self, streams, conn):
        self.streams = streams
        self.conn = conn

    def add_stream(self, s):
        self.streams.add_stream(s)

    def throw(self, err):
        for strm in self.streams:
            strm.framequeue.put(stream.StreamEvent(stream.StreamToken.ERROR_TOKEN, err))

    def quit(self):
        for strm in self.streams:
            strm.framequeue.put(
                stream.StreamEvent(stream.StreamToken.CLOSE_TOKEN, None)
            )

    def process(self, f):
        if f.frame_type == frame.HTTP2_FRAME_HEADERS:
            f.decode_headers(self.conn.server_hpack)
        if f.frame_type == frame.HTTP2_FRAME_SETTINGS:
            self.conn.update_server_settings(f.dict)
        if f.frame_type == frame.HTTP2_FRAME_WINDOW_UPDATE:
            if f.streamid == 0:
                self.conn.outbound_window += f.increment
            else:
                self.streams[f.streamid].outbound_window += f.increment
        if f.streamid == 0:
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                error.throw(f, conn=self.conn)
            if f.frame_type == frame.HTTP2_FRAME_PING:
                return frame.PingFrame(f.data, ack=True)

        else:
            target_stream = self.streams[f.streamid]
            err, closed = target_stream.error_check(f)
            if err is not None:
                self.conn.close_on_error(err)
                raise err
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                raise error.ProtocolError(
                    "GOAWAY frame sent with a stream id other than 0"
                )
            else:
                if closed:
                    token = stream.StreamToken.CLOSE_TOKEN
                else:
                    token = stream.StreamToken.FRAME_TOKEN
                target_stream.framequeue.put(stream.StreamEvent(token, f))
                if f.frame_type == frame.HTTP2_FRAME_DATA:
                    target_stream.window.received_frame(f.payload_length)
                    increment = target_stream.window.process(f.payload_length)
                    if increment != 0:
                        return frame.WindowUpdateFrame(increment, streamid=f.streamid)


class AsyncFrameQueue:
    def __init__(self, streams, conn):
        self.streams = streams
        self.conn = conn

    def add_stream(self, s):
        self.streams.add_stream(s)

    async def throw(self, err):
        for strm in self.streams:
            await strm.framequeue.put(
                stream.StreamEvent(stream.StreamToken.ERROR_TOKEN, err)
            )

    async def quit(self):
        for strm in self.streams:
            await strm.framequeue.put(
                stream.StreamEvent(stream.StreamToken.CLOSE_TOKEN, None)
            )

    async def process(self, f):
        if f.frame_type == frame.HTTP2_FRAME_HEADERS:
            f.decode_headers(self.conn.server_hpack)
        if f.frame_type == frame.HTTP2_FRAME_SETTINGS:
            self.conn.update_server_settings(f.dict)
        if f.frame_type == frame.HTTP2_FRAME_WINDOW_UPDATE:
            if f.streamid == 0:
                self.conn.outbound_window += f.increment
            else:
                self.streams[f.streamid].outbound_window += f.increment
        if f.streamid == 0:
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                await error.async_throw(f, conn=self.conn)
            if f.frame_type == frame.HTTP2_FRAME_PING:
                return frame.PingFrame(f.data, ack=True)

        else:
            target_stream = self.streams[f.streamid]
            err, closed = await target_stream.error_check(f)
            if err is not None:
                await self.conn.close_on_error(err)
                raise err
            if f.frame_type == frame.HTTP2_FRAME_GOAWAY:
                raise error.ProtocolError(
                    "GOAWAY frame sent with a stream id other than 0"
                )
            else:
                if closed:
                    token = stream.StreamToken.CLOSE_TOKEN
                else:
                    token = stream.StreamToken.FRAME_TOKEN
                await target_stream.framequeue.put(stream.StreamEvent(token, f))
                if f.frame_type == frame.HTTP2_FRAME_DATA:
                    target_stream.window.received_frame(f.payload_length)
                    increment = target_stream.window.process(f.payload_length)
                    if increment != 0:
                        return frame.WindowUpdateFrame(increment, streamid=f.streamid)
