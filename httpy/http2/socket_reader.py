class SocketReader:
    def __init__(self, sock):
        self.sock = sock

    def read(self, nbytes):
        bytes_read = 0
        buf = bytearray()
        while bytes_read < nbytes:
            chunk = self.sock.recv(1)
            if not chunk:
                continue
            buf.append(ord(chunk))
            bytes_read += 1
        return bytes(buf)

    @property
    def closed(self):
        return self.sock.fileno() == -1
