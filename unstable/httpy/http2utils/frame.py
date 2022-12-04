import io
import struct

HTTP2_FRAME_DATA=0x00
HTTP2_FRAME_HEADERS=0x01
HTTP2_FRAME_PRIORITY=0x02
HTTP2_FRAME_RST_STREAM=0x03
HTTP2_FRAME_SETTINGS=0x04
HTTP2_FRAME_PUSH_PROMISE=0x05
HTTP2_FRAME_PING=0x06
HTTP2_FRAME_GOAWAY=0x07
HTTP2_FRAME_WINDOW_UPDATE=0x08
HTTP2_FRAME_CONTINUATION=0x09
HTTP2_FRAME_ALTSVC=0x0a
HTTP2_FRAME_ORIGIN=0x0c
HTTP2_FRAME_PRIORITY_UPDATE=0x10
class HTTP2Error(Exception): pass
class PayloadOverflow(HTTP2Error):pass
class InvalidStreamID(HTTP2Error):pass
class HTTP2Frame:
    def __init__(self,type,payload,flags,streamid=0x00):
        if streamid> 2**31-1:
            raise InvalidStreamID(
                    "invalid stream: stream IDs must be less than 2,147,483,647"
                    )
        if len(payload)>2**14:
            raise PayloadOverflow(
                    "can't send payloads larger than 16,384 bytes, SETTINGS_MAX_FRAME_SIZE support will be added later."
                    )
        self.type=type
        self.payload=payload
        self.flags=flags
        self.streamid=streamid
    def toio(self):
        rio = io.BytesIO()
        pl= len(self.payload)
        rio.write(struct.pack(">I",pl)[2:])
        rio.write(struct.pack("B",self.type))
        rio.write(struct.pack("B",self.flags))
        rio.write(struct.pack("I",self.streamid))
        rio.write(self.payload)
        return rio



        
