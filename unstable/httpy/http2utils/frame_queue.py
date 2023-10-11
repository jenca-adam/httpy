import queue


class FrameQueue:
    def __init__(self, streams):
        self.streams = streams

    def add_stream(self, stream):
        self.streams.append(stream)

    def send_frame(self, frame):
        self.stream
