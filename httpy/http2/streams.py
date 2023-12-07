from .stream import StreamState, Stream


class Streams:
    def __init__(self, max_concurrent_streams, conn):
        self.max_concurrent_streams = max_concurrent_streams
        self.inbound = []
        self.conn = conn
        self.outbound = []

    def add_stream(self, s):
        if s.streamid % 2:
            self.outbound.append(s)
        else:
            self.inbound.append(s)

    def __iter__(self):
        return iter(self.outbound)

    def close_stream(self, streamid):
        streamlist = self.outbound if (streamid % 2) else self.inbound
        try:
            stream = next(filter(lambda x: x.streamid == streamid, streamlist))
            if stream.state == StreamState.CLOSED:
                raise IndexError("Stream alredy closed")
        except (StopIteration, IndexError):
            raise IndexError(
                f"can't close stream: stream at {streamid:#x} already closed or not yet created"
            )
        stream.state = StreamState.CLOSED

    def __getitem__(self, streamid):
        for s in self.outbound if streamid % 2 else self.inbound:
            if s.streamid == streamid:
                return s
        s = Stream(streamid, self.conn, self.conn.settings["initial_window_size"])
        self.add_stream(s)
        return s
