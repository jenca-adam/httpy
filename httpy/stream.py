class Stream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
        self.status, self.headers = next(self.gen)
        self.ok = self.status == 200
        self.state = None

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
        self.headers = None
        self.status = None
        self.state = None

    async def load_headers(self):
        self.status, self.headers = await anext(self.gen)
        self.ok = self.status == 200

    async def read(self, nbytes):
        if self.headers is None:
            await self.load_headers()
        while len(self.buffer) < nbytes:
            try:
                chunk, self.state = await anext(self.gen)
                if chunk is None:
                    break
                self.buffer.extend(chunk)

            except (StopAsyncIteration, TypeError):
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)
