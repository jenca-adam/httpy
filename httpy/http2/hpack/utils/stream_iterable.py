class StreamIterable:
    def __init__(self, stream, chunksize=1, func=None):
        self.stream = stream
        self.pos = stream.tell()
        self.func = func
        self.chunksize = chunksize

    def __iter__(self):
        return self

    def __next__(self):
        n = self.stream.read(self.chunksize)
        if not n:
            raise StopIteration
        self.pos += 1
        if self.func is None:
            return n
        return self.func(n)

    def __getitem__(self, index):
        q = self.pos
        self.stream.seek(index)
        t = next(self)
        self.pos = q
        self.stream.seek(q)
        return t

    def get_next(self):
        try:
            return self.stream.getbuffer()[self.stream.tell()]
        except IndexError:
            return None

    def read(self, size):
        self.pos += size
        return self.stream.read(size)

    def read_back(self, size):
        p = self.stream.tell()
        if size > 1:
            g = map(self.func, self.stream.read(size))
        else:
            g = self.func(self.stream.read(size))
        self.stream.seek(p)
        return g
