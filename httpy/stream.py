class Stream:
    def __init__(self, generator):
        self.gen = generator
        self._started = False
        self.buffer = bytearray()
        self.status, self.headers = next(self.gen)
        self.ok=self.status==200
    def read(self, nbytes):
        while len(self.buffer) < nbytes:
            try:
                chunk, self.state = next(self.gen)
                self.buffer.extend(chunk)
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)


class AsyncStream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
    async def load_headers(self):
        self.headers, self.status = await anext(self.gen)
    async def read(self, nbytes):
        while len(self.buffer) < nbytes:
            try:
                self.buffer.extend(await anext(self.gen))
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)
