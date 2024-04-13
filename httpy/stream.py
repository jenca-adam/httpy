class Stream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
        self.status, self.headers = next(self.gen)
        self.ok = self.status == 200

    def read(self, nbytes):
        while len(self.buffer) < nbytes:
            try:
                chunk, self.state = next(self.gen)
                if chunk is None:
                    break
                self.buffer.extend(chunk)
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)


class AsyncStream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
        self._headers_loaded = False
        self.headers=None
        self.status = None
    async def load_headers(self):
        self.headers, self.status = await anext(self.gen)

    async def read(self, nbytes):
        if not self._headers_loaded:
            self.load_headers()
            self._headers_loaded=True
        while len(self.buffer) < nbytes:
            try:
                self.buffer.extend(await anext(self.gen))
            except (StopIteration, TypeError):
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)
