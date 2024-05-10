class File(io.IOBase):
    """Class  used to upload files"""

    def __init__(self, buffer, filename, content_type=None):
        self.parent = super().__init__()
        if content_type is None:
            content_type = force_string(
                mimetypes.guess_type(os.path.split(filename)[1])[0]
            )
        content_type = force_string(content_type)

        self.size = len(buffer)
        self.buffer = io.BytesIO(buffer)

        self.name = force_string(os.path.split(filename)[1])
        self.mode = "rb"
        self.content_type = content_type

    def read(self, size=-1):
        return self.buffer.read(size)

    def save(self, destination):
        if os.path.exists(destination):
            if os.path.isdir(destination):
                destination = os.path.join(destination, self.name)

        return open(destination, "wb").write(self.buffer.getvalue())

    def seek(self, pos):
        self.buffer.seek(pos)

    def tell(self):
        return self.buffer.tell()

    def write(self, anything):
        raise io.UnsupportedOperation("not writable")

    def value(self):
        return self.buffer.getvalue()

    @classmethod
    def open(self, file):
        reader = open(file, "rb")
        return File(reader.read(), file)
