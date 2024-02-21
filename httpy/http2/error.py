import sys
import enum
import warnings
from ssl import SSLError


class ErrType(enum.Enum):
    CONNECTION = 0
    STREAM = 1


class Refuse(Exception):
    pass


class HTTP2Error(Exception):
    def __init__(self, *args, errtype=None, send=True):
        self.errtype = self.errtype or errtype
        self.send = send
        if self.errtype is None and send:
            warnings.warn(
                Warning("errtype is None. error message will not reach the peer")
            )
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
    errtype = None


class PayloadOverflow(HTTP2Error):
    pass


class InvalidStreamID(HTTP2Error):
    pass


def throw(frame, send=False, conn=None):
    from .frame import HTTP2_FRAME_RST_STREAM, HTTP2_FRAME_GOAWAY

    errcode = frame.errcode
    if frame.frame_type not in (HTTP2_FRAME_RST_STREAM, HTTP2_FRAME_GOAWAY):
        return
    if errcode > 0:
        message = (
            f"Received a RST_STREAM frame: {ERRORS[errcode][0]}"
            if frame.frame_type == HTTP2_FRAME_RST_STREAM
            else f"Received a GOAWAY frame: {ERRORS[errcode][0]}: {frame.debugdata}"
        )
    else:
        if frame.frame_type == HTTP2_FRAME_GOAWAY and conn is not None:
            conn.close_socket()

        return
    try:
        err = ERROR_INSTANCES[errcode](message, send=send)
    except IndexError:
        raise ERROR_INSTANCES[1](
            "unknown error code", errtype=ErrType.CONNECTION
        )  # Protocol error
    raise err


async def async_throw(frame, send=False, conn=None):
    from .frame import HTTP2_FRAME_RST_STREAM, HTTP2_FRAME_GOAWAY

    errcode = frame.errcode
    if frame.frame_type not in (HTTP2_FRAME_RST_STREAM, HTTP2_FRAME_GOAWAY):
        return
    if errcode > 0:
        message = (
            f"Received a RST_STREAM frame: {ERRORS[errcode][0]}"
            if frame.frame_type == HTTP2_FRAME_RST_STREAM
            else f"Received a GOAWAY frame: {ERRORS[errcode][0]}: {frame.debugdata}"
        )
    else:
        if frame.frame_type == HTTP2_FRAME_GOAWAY and conn is not None:
            await conn.close_socket()

        return
    try:
        err = ERROR_INSTANCES[errcode](message, send=send)
    except IndexError:
        raise ERROR_INSTANCES[1](
            "unknown error code", errtype=ErrType.CONNECTION
        )  # Protocol error
    raise err


ERRORS = [
    ("NO_ERROR", None),
    ("PROTOCOL_ERROR", ErrType.CONNECTION),
    ("INTERNAL_ERROR", ErrType.CONNECTION),
    ("FLOW_CONTROL_ERROR", ErrType.CONNECTION),
    ("SETTINGS_TIMEOUT", ErrType.CONNECTION),
    ("STREAM_CLOSED", ErrType.STREAM),
    ("FRAME_SIZE_ERROR", ErrType.STREAM),
    ("REFUSED_STREAM", ErrType.STREAM),
    ("CANCEL", ErrType.STREAM),
    ("COMPRESSION_ERROR", ErrType.CONNECTION),
    ("CONNECT_ERROR", ErrType.CONNECTION),
    ("ENHANCE_YOUR_CALM", ErrType.CONNECTION),
    ("INADEQUATE_SECURITY", ErrType.CONNECTION),
    ("HTTP_1_1_REQUIRED", ErrType.CONNECTION),
]
ERROR_INSTANCES = []
__module__ = sys.modules[__name__]
for index, (err, type) in enumerate(ERRORS):

    class UNKNOWN_ERROR(HTTP2Error):
        __qualname__ = err
        __name__ = err
        name = err
        code = index
        errtype = type

    setattr(__module__, err, UNKNOWN_ERROR)
    ERROR_INSTANCES.append(UNKNOWN_ERROR)
