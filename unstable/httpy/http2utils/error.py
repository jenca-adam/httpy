import sys


class HTTP2Error(Exception):
    pass


class ProtocolError(HTTP2Error):
    def __init__(self, *args):
        if args:
            args = list(args)
            args[0] = f"(ERR{hex(self.code)}): " + args[0]
            self.comment = None
            if len(args) > 1:
                self.comment = args[1]
                del args[1]
                self.add_note(self.comment)
        super().__init__(*args)

    name = NotImplemented
    code = NotImplemented


class PayloadOverflow(HTTP2Error):
    pass


class InvalidStreamID(HTTP2Error):
    pass


PROTOCOL_ERRORS = [
    "NO_ERROR",
    "PROTOCOL_ERROR",
    "INTERNAL_ERROR",
    "FLOW_CONTROL_ERROR",
    "SETTINGS_TIMEOUT",
    "STREAM_CLOSED",
    "FRAME_SIZE_ERROR",
    "REFUSED_STREAM",
    "CANCEL",
    "COMPRESSION_ERROR",
    "CONNECT_ERROR",
    "ENHANCE_YOUR_CALM",
    "INADEQUATE_SECURITY",
    "HTTP_1_1_REQUIRED",
]
ERROR_INSTANCES = []
__module__ = sys.modules[__name__]
for index, err in enumerate(PROTOCOL_ERRORS):

    class UNKNOWN_ERROR(ProtocolError):
        __qualname__ = err
        __name__ = err
        name = err
        code = index

    setattr(__module__, err, UNKNOWN_ERROR)
    ERROR_INSTANCES.append(UNKNOWN_ERROR)
