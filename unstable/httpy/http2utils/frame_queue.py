import queue


class FrameQueue:
    def __init__(self, streams):
        self.streams = streams

    def add_stream(self, stream):
        self.streams.add_stream(stream)

    def process(self, frame):
        self.streams[frame.streamid].framequeue.put(frame)
