from httpy.errors import HTTPyError


class HPackError(HTTPyError):
    pass


class EncodingError(HPackError):
    pass


class DecodingError(HPackError):
    pass


class HuffmanError(HPackError):
    pass


class HuffmanDecodingError(HuffmanError, DecodingError):
    pass


class HuffmanEncodingError(HuffmanError, EncodingError):
    pass
