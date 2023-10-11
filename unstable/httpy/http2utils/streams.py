class Streams:
    def __init__(self, max_concurrent_streams, conn):
        self.max_concurrent_streams = max_concurrent_streams
        self.streams = []
        self.inbound = []
        self.conn = conn
        self.outbound = []

    def add_stream(self, stream):
        if stream.streamid % 2:
            self.outbound.append(stream)
        else:
            self.inbound.append(stream)
        self.streams.append(stream)

    def __getitem__(self, streamid):
        for s in self.streams:
            if s.streamid == streamid:
                return stream
        s = stream.Stream(streamid, self.conn)
        self.add_stream(s)
        return s
