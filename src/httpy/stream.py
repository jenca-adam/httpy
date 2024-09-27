class Stream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
        self.status, self.headers, self.state = next(self.gen)
        self.ok = self.status == 200
        self.bytes_read = 0

    def read(self, nbytes=None):

        while nbytes is None or len(self.buffer) < nbytes:
            try:
                chunk, self.state = next(self.gen)
                if chunk is None:
                    break
                self.buffer.extend(chunk)
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        self.bytes_read += len(result)
        return bytes(result)


class AsyncStream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()
        self.headers = None
        self.status = None
        self.state = None
        self.ok = None
        self.bytes_read = 0

    async def load_state(self):
        self.status, self.headers, self.state = await anext(self.gen)
        self.ok = self.status == 200

    async def read(self, nbytes=None):
        if self.state is None:
            await self.load_state()
        while nbytes is None or len(self.buffer) < nbytes:
            try:
                chunk, self.state = await anext(self.gen)
                if chunk is None:
                    break
                self.buffer.extend(chunk)

            except (StopAsyncIteration, TypeError):
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        self.bytes_read += len(result)
        return bytes(result)
