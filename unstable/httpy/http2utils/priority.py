class StreamDependency:  # dummy class
    def __init__(self, stream, exc=False):
        self.stream = stream
        self.exc = exc

    def __eq__(self, o):
        return o.stream == self.stream and o.exc == self.exc

    def __repr__(self):
        return f"<StreamDependency{' exclusive' if self.exc else ''} {self.stream}>"
