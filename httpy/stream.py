class Stream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()

    def read(self, nbytes):
        while len(self.buffer) < nbytes:
            try:
                self.buffer.extend(next(self.gen))
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)


class AsyncStream:
    def __init__(self, generator):
        self.gen = generator
        self.buffer = bytearray()

    async def read(self, nbytes):
        while len(self.buffer) < nbytes:
            try:
                self.buffer.extend(await anext(self.gen))
            except StopIteration:
                break
        result, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
        return bytes(result)
