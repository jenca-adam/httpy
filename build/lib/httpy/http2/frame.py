import io
import struct
import enum
import socket
import asyncio

from .error import *
from .priority import StreamDependency
from .socket_reader import SocketReader

HTTP2_FRAME_DATA = 0x00
HTTP2_FRAME_HEADERS = 0x01
HTTP2_FRAME_PRIORITY = 0x02
HTTP2_FRAME_RST_STREAM = 0x03
HTTP2_FRAME_SETTINGS = 0x04
HTTP2_FRAME_PUSH_PROMISE = 0x05
HTTP2_FRAME_PING = 0x06
HTTP2_FRAME_GOAWAY = 0x07
HTTP2_FRAME_WINDOW_UPDATE = 0x08
HTTP2_FRAME_CONTINUATION = 0x09
HTTP2_FRAME_ALTSVC = 0x0A
HTTP2_FRAME_ORIGIN = 0x0C
HTTP2_FRAME_PRIORITY_UPDATE = 0x10


class ConnectionToken(enum.Enum):
    CONNECTION_CLOSE = 0


class HTTP2Frame:
    frame_type = -1

    def __init__(
        self,
        instance=None,
        type=None,
        payload=None,
        flags=0x0,
        streamid=0x00,
        frame_size=16384,
        **_,
    ):
        self.type = type or getattr(instance, "frame_type", None)
        self.payload = (
            payload
            or getattr(
                instance,
                "_generate_payload",
                lambda *x: None,
            )
        )()
        self.payload_length = len(self.payload)
        self.flags = flags or getattr(instance, "flags", 0x0)
        self.streamid = streamid
        if self.streamid > 2**31 - 1:
            raise InvalidStreamID(
                "invalid stream: stream IDs must be less than 2,147,483,647"
            )
        if len(self.payload) > frame_size:
            raise PayloadOverflow("MAX_FRAME_SIZE exceeded")

    def tobytes(self):
        return b"".join(
            [
                (struct.pack("!I", len(self.payload))[1:]),
                (struct.pack("!B", self.type)),
                (struct.pack("!B", self.flags)),
                (struct.pack("!I", self.streamid)),
                (self.payload),
            ]
        )

    def _toio(self):
        return io.BytesIO(self.tobytes())

    def _generate_payload(self):
        raise NotImplementedError


class DataFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_DATA

    def __init__(self, data, padding=0, end_stream=False, **kwargs):
        self.data = data
        self.padding = padding
        self.end_stream = end_stream
        self.flags = 0 | (0x1 if end_stream else 0) | (0x8 if padding > 0 else 0)
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return b"".join(
            [
                struct.pack("!B", self.padding) if self.padding > 0 else b"",
                self.data,
                b"\x00" * self.padding,
            ]
        )

    @classmethod
    def frombytes(cls, payload, payload_length, streamid, flags, **kwargs):
        if streamid == 0x0:
            raise PROTOCOL_ERROR("DATA frame sent without a stream id")
        pio = io.BytesIO(payload)
        if flags & 0x8:  # padded
            padding_length, *_ = struct.unpack("!B", pio.read(1))
            if padding_length >= payload_length:
                raise PROTOCOL_ERROR(
                    "DATA frame padding too large",
                    f"{padding_length}>={payload_length}",
                )
            data_length = payload_length - padding_length - 1
        else:
            data_length = payload_length
            padding_length = 0
        data = pio.read(data_length)
        if len(data) != data_length:
            raise PROTOCOL_ERROR("Unexpected EOF while reading data from DATA frame")
        padding = pio.read(padding_length)
        if len(padding) != padding_length:
            raise PROTOCOL_ERROR("Unexpected EOF while reading padding in DATA frame")
        if set(padding) and set(padding) != {0}:
            raise PROTOCOL_ERROR(
                "padding in DATA frame not set to zero", f"Padding: {padding!r}"
            )
        return cls(
            data,
            padding_length,
            bool(flags & 0x1),
            streamid=streamid,
            flags=flags,
            **kwargs,
        )


class HeadersFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_HEADERS

    def __init__(
        self,
        header_fragment,
        pad_length=0,
        priority_weight=None,
        stream_dependency=None,
        end_stream=False,
        end_headers=False,
        **kwargs,
    ):
        self.header_fragment = header_fragment
        self.decoded_headers = None
        self.pad_length = pad_length
        self.priority_weight = priority_weight
        self.stream_dependency = stream_dependency
        self.end_stream = end_stream
        self.end_headers = end_headers
        self.flags = (
            0
            | (0x1 if end_stream else 0)
            | (0x4 if end_headers else 0)
            | (0x8 if pad_length > 0 else 0)
            | (
                0x20
                if stream_dependency is not None or priority_weight is not None
                else 0
            )
        )
        super().__init__(self, **kwargs)

    def decode_headers(self, hpack):
        self.decoded_headers = hpack.decode_headers(self.header_fragment)

    @classmethod
    def frombytes(cls, payload, payload_length, flags, streamid, **kwargs):
        if streamid == 0x0:
            raise PROTOCOL_ERROR("HEADERS frame sent without a stream ID")
        pio = io.BytesIO(payload)
        if flags & 0x8:  # padded
            pad_length, *_ = struct.unpack("!B", pio.read(1))
        else:
            pad_length = 0
        if flags & 0x20:  # priority
            _sdint, *_ = struct.unpack("!I", pio.read(4))
            priority_weight, *_ = struct.unpack("!B", pio.read(1))
            stream_dependency = StreamDependency(
                _sdint & 0x7FFFFFFF, bool(_sdint & 0x80000000)
            )

        else:
            stream_dependency = None
            priority_weight = None

        fragment_length = payload_length - pad_length - pio.tell()
        header_fragment = pio.read(fragment_length)
        if len(header_fragment) != fragment_length:
            raise PROTOCOL_ERROR("Unexpected EOF while reading data in HEADERS frame")
        padding = pio.read(pad_length)
        if len(padding) != pad_length:
            raise PROTOCOL_ERROR(
                "Unexpected EOF while reading padding in HEADERS frame"
            )
        if set(padding) and set(padding) != {0}:
            raise PROTOCOL_ERROR(
                "padding in HEADERS frame not set to zero", f"Padding: {padding!r}"
            )
        return cls(
            header_fragment,
            pad_length,
            priority_weight,
            stream_dependency,
            bool(flags & 0x1),
            bool(flags & 0x4),
            flags=flags,
            streamid=streamid,
            **kwargs,
        )

    def _generate_payload(self):
        return b"".join(
            [
                struct.pack("!B", self.pad_length) if self.pad_length > 0 else b"",
                (
                    struct.pack(
                        "!I",
                        self.stream_dependency.stream
                        | 0x80000000 * self.stream_dependency.exc,
                    )
                    if self.stream_dependency is not None
                    else b""
                ),
                (
                    struct.pack("!B", self.priority_weight)
                    if self.priority_weight is not None
                    else b""
                ),
                self.header_fragment,
                self.pad_length * b"\x00",
            ]
        )


class PriorityFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_PRIORITY

    def __init__(self, stream_dependency, priority_weight, **kwargs):
        self.stream_dependency = stream_dependency
        self.priority_weight = priority_weight
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return b"".join(
            [
                struct.pack(
                    "!I",
                    self.stream_dependency.stream
                    | 0x80000000 * self.stream_dependency.exc,
                ),
                struct.pack("!B", self.priority_weight),
            ]
        )

    @classmethod
    def frombytes(cls, payload, payload_length, streamid, **kwargs):
        pio = io.BytesIO(payload)
        if payload_length != 5:
            raise FRAME_SIZE_ERROR(
                "PRIORITY frame size other than 5 octets", f"size: {payload_length}"
            )
        if streamid == 0x0:
            raise PROTOCOL_ERROR("PRIORITY frame not associated with a stream")
        _sdint, *_ = struct.unpack("!I", pio.read(4))
        priority_weight, *_ = struct.unpack("!B", pio.read(1))
        stream_dependency = StreamDependency(
            _sdint & 0x7FFFFFFF, bool(_sdint & 0x80000000)
        )
        return cls(stream_dependency, priority_weight, streamid=streamid, **kwargs)


class RstStreamFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_RST_STREAM

    def __init__(self, errcode, **kwargs):
        self.errcode = errcode
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return struct.pack("!I", self.errcode)

    @classmethod
    def frombytes(cls, payload, payload_length, streamid, **kwargs):
        if streamid == 0x0:
            raise PROTOCOL_ERROR("RST_STREAM frame sent without a stream ID")

        if payload_length != 4:
            raise FRAME_SIZE_ERROR(
                "RST_STREAM frame size other than 4 octets", f"size: {payload_length}"
            )
        return cls(struct.unpack("!I", payload)[0], **kwargs, streamid=streamid)


class SettingsFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_SETTINGS

    def __init__(
        self,
        header_table_size=None,
        enable_push=None,
        max_concurrent_streams=None,
        initial_window_size=None,
        max_frame_size=None,
        max_header_list_size=None,
        ack=False,
        **kwargs,
    ):
        (
            self.header_table_size,
            self.enable_push,
            self.max_concurrent_streams,
            self.initial_window_size,
            self.max_frame_size,
            self.max_header_list_size,
        ) = (
            header_table_size,
            enable_push,
            max_concurrent_streams,
            initial_window_size,
            max_frame_size,
            max_header_list_size,
        )
        self.dict = {
            "header_table_size": self.header_table_size,
            "enable_push": self.enable_push,
            "max_concurrent_streams": self.max_concurrent_streams,
            "initial_window_size": self.initial_window_size,
            "max_frame_size": self.max_frame_size,
            "max_header_list_size": self.max_header_list_size,
        }
        self.payload = self._generate_payload() if not ack else ""
        self.flags = 0x80 if ack else 0
        self.type = 0x4
        self.ack = ack
        super().__init__(self, frame_size=max_frame_size or 16384, **kwargs)

    def _generate_payload(self):
        result = []
        for index, value in enumerate(
            [
                self.header_table_size,
                self.enable_push,
                self.max_concurrent_streams,
                self.initial_window_size,
                self.max_frame_size,
                self.max_header_list_size,
            ]
        ):
            if value is None:
                continue
            result.append(struct.pack("!H", index + 1))
            result.append(struct.pack("!I", int(value)))
        return b"".join(result)

    @classmethod
    def frombytes(cls, payload, payload_length, flags, streamid, **kwargs):
        if streamid > 0:
            raise PROTOCOL_ERROR(
                "Stream ID for a SETTINGS frame not 0x0", f"streamid:{hex(streamid)}"
            )
        pio = io.BytesIO(payload)
        if payload_length % 6 != 0:
            raise FRAME_SIZE_ERROR(
                "SETTINGS frame size not a multiple of 6", f"size:{payload_length}"
            )
        ack = bool(flags & 0x80)
        if ack and payload_length != 0:
            raise FRAME_SIZE_ERROR("SETTINGS frame with the ACK flag set not empty")
        names = [
            None,
            "header_table_size",
            "enable_push",
            "max_concurrent_streams",
            "initial_window_size",
            "max_frame_size",
            "max_header_list_size",
        ]
        settings = {}
        for _ in range(payload_length // 6):
            index, *_ = struct.unpack("!H", pio.read(2))
            _v = pio.read(4)
            value, *_ = struct.unpack("!I", _v)

            if index == 0x2:  # ENABLE_PUSH
                if value > 1:
                    raise PROTOCOL_ERROR("Invalid SETTINGS_ENABLE_PUSH value")
                value = bool(value)
            elif index == 0x4:  # INITIAL_WINDOW_SIZE
                if value > 0x7FFFFFFF:
                    raise FLOW_CONTROL_ERROR(
                        "SETTINGS_INITIAL_WINDOW_SIZE value too large"
                    )
            elif index == 0x5:  # MAX_FRAME_SIZE
                if value not in range(0x4000, 0x1000000):
                    raise PROTOCOL_ERROR("Invalid SETTINGS_MAX_FRAME_SIZE value")
            if index >= len(names) or names[index] is None:
                continue  # IGNORE
            settings[names[index]] = value
        return cls(ack=ack, flags=flags, streamid=streamid, **settings, **kwargs)


class PushPromiseFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_PUSH_PROMISE

    def __init__(
        self,
        promised_stream,
        header_fragment,
        pad_length=0,
        end_headers=False,
        **kwargs,
    ):
        self.promised_stream = promised_stream
        self.header_fragment = header_fragment
        self.pad_length = pad_length
        self.flags = 0 | 0x4 if end_headers else 0 | 0x8 if pad_length > 0 else 0
        super.__init__(self, **kwargs)

    def _generate_payload(self):
        return b"".join(
            [
                struct.pack("!B", pad_length) if pad_length > 0 else b"",
                struct.pack("!I", self.promised_stream),
                self.header_fragment,
                b"\x00" * self.pad_length,
            ]
        )

    @classmethod
    def frombytes(cls, payload, payload_length, flags, streamid, **kwargs):
        if streamid == 0x0:
            raise PROTOCOL_ERROR("PUSH_PROMISE frame sent without a stream ID")

        pio = io.BytesIO(payload)
        if flags & 0x8:
            pad_length, *_ = struct.unpack("!B", pio.read(1))
        promised_stream, *_ = struct.unpack("!I", pio.read(4))
        fragment_length = payload_length - pad_length - pio.tell()
        header_fragment = pio.read(fragment_length)
        if len(header_fragment) != fragment_length:
            raise FRAME_SIZE_ERROR(
                "Unexpected EOF while reading data in PUSH_PROMISE frame"
            )
        padding = pio.read(pad_length)
        if len(padding) != pad_length:
            raise PROTOCOL_ERROR(
                "Unexpected EOF while reading padding in PUSH_PROMISE frame"
            )
        if set(padding) and set(padding) != {0}:
            raise PROTOCOL_ERROR(
                "padding in PUSH_PROMISE frame not set to zero", f"Padding: {padding!r}"
            )
        return cls(
            promised_stream,
            header_fragment,
            pad_length,
            bool(flags & 0x4),
            streamid=streamid,
            flags=flags,
            **kwargs,
        )


class PingFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_PING

    def __init__(self, data=b"\x00" * 8, ack=False, **kwargs):
        self.data = data
        self.flags = 1 if ack else 0
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return self.data

    @classmethod
    def frombytes(cls, payload, payload_length, flags, streamid, **kwargs):
        if payload_length != 8:
            raise FRAME_SIZE_ERROR(
                "PING frame size other than 8 octets", f"size: {payload_length}"
            )
        if streamid != 0x0:
            raise PROTOCOL_ERROR(
                "Stream ID for a PING frame not 0x0", f"streamid:{hex(streamid)}"
            )
        return cls(payload, bool(flags), flags=flags, streamid=streamid, **kwargs)


class GoAwayFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_GOAWAY

    def __init__(self, last_stream_id, error_code, debugdata=b"", **kwargs):
        self.last_stream_id = last_stream_id
        self.errcode = error_code
        self.debugdata = debugdata
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return b"".join(
            [
                struct.pack("!I", self.last_stream_id),
                struct.pack("!I", self.errcode),
                self.debugdata,
            ]
        )

    @classmethod
    def frombytes(cls, payload, streamid, **kwargs):
        if streamid != 0x0:
            raise PROTOCOL_ERROR(
                "Stream ID for a GOAWAY frame not 0x0", f"streamid:{hex(streamid)}"
            )
        pio = io.BytesIO(payload)
        last_stream_id, *_ = struct.unpack("!I", pio.read(4))
        error_code, *_ = struct.unpack("!I", pio.read(4))
        debugdata = pio.read()
        return cls(last_stream_id, error_code, debugdata, streamid=streamid, **kwargs)


class WindowUpdateFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_WINDOW_UPDATE

    def __init__(self, increment, **kwargs):
        self.increment = increment
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return struct.pack("!I", self.increment)

    @classmethod
    def frombytes(cls, payload, payload_length, **kwargs):
        if payload_length != 4:
            raise FRAME_SIZE_ERROR(
                "WINDOW_UPDATE frame size other than 4 octets",
                f"size: {payload_length}",
            )
        increment, *_ = struct.unpack("!I", payload)
        if increment == 0:
            raise PROTOCOL_ERROR("WINDOW_UPDATE increment is zero")
        return cls(increment, **kwargs)


class ContinuationFrame(HTTP2Frame):
    frame_type = HTTP2_FRAME_CONTINUATION

    def __init__(contents, end_headers=False, **kwargs):
        self.contents = contents
        self.flags = 0x4 if end_headers else 0x0
        super().__init__(self, **kwargs)

    def _generate_payload(self):
        return self.contents

    @classmethod
    def frombytes(cls, payload, streamid, flags, **kwargs):
        if streamid == 0x0:
            raise PROTOCOL_ERROR("CONTINUATION frame sent without a stream ID")
        return cls(payload, bool(flags & 0x4), flags=flags, streamid=streamid, **kwargs)


def parse_data(stream):
    if isinstance(stream, socket.socket):
        stream = SocketReader(stream)
    if stream.closed:
        return ConnectionToken.CONNECTION_CLOSE
    try:
        payload_length, *_ = struct.unpack("!I", b"\x00" + stream.read(3))
        frame_type, *_ = struct.unpack("!B", stream.read(1))
        flags, *_ = struct.unpack("!B", stream.read(1))
        streamid, *_ = struct.unpack("!I", stream.read(4))
        payload = stream.read(payload_length)
    except (struct.error, SSLError):  # read fail
        raise
        return ConnectionToken.CONNECTION_CLOSE
    except ValueError as e:
        if "PyMemoryView_FromBuffer(): info->buf must not be NULL" in str(
            e
        ):  # read fail #2
            return ConnectionToken.CONNECTION_CLOSE
        raise
    if frame_type not in FRAMES:
        return None
    return payload, payload_length, streamid, flags, frame_type


def parse(stream):
    return _parse(parse_data(stream))


def _parse(data):
    if data is None:
        return None
    payload, payload_length, streamid, flags, frame_type = data

    return FRAMES[frame_type].frombytes(
        payload=payload, payload_length=payload_length, streamid=streamid, flags=flags
    )


async def async_parse_data(reader):
    try:
        payload_length, *_ = struct.unpack("!I", b"\x00" + await reader.read(3))
        frame_type, *_ = struct.unpack("!B", await reader.read(1))
        flags, *_ = struct.unpack("!B", await reader.read(1))
        streamid, *_ = struct.unpack("!I", await reader.read(4))
        payload = await reader.readexactly(payload_length)
    except (
        struct.error,
        SSLError,
        asyncio.IncompleteReadError,
        asyncio.exceptions.CancelledError,
    ):  # read fail
        return ConnectionToken.CONNECTION_CLOSE
    except ValueError as e:
        if "PyMemoryView_FromBuffer(): info->buf must not be NULL" in str(
            e
        ):  # read fail #2
            return ConnectionToken.CONNECTION_CLOSE
        raise
    if frame_type not in FRAMES:
        return None
    return payload, payload_length, streamid, flags, frame_type


async def async_parse(reader):
    return _parse(await async_parse_data(reader))


FRAMES = {
    HTTP2_FRAME_DATA: DataFrame,
    HTTP2_FRAME_HEADERS: HeadersFrame,
    HTTP2_FRAME_PRIORITY: PriorityFrame,
    HTTP2_FRAME_SETTINGS: SettingsFrame,
    HTTP2_FRAME_PUSH_PROMISE: PushPromiseFrame,
    HTTP2_FRAME_PING: PingFrame,
    HTTP2_FRAME_GOAWAY: GoAwayFrame,
    HTTP2_FRAME_WINDOW_UPDATE: WindowUpdateFrame,
    HTTP2_FRAME_CONTINUATION: ContinuationFrame,
    HTTP2_FRAME_RST_STREAM: RstStreamFrame,
}
