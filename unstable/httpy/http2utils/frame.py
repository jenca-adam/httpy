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
    def __init__(self,type,payload,flags,streamid=0x00,frame_size=16384):
        if streamid> 2**31-1:
            raise InvalidStreamID(
                    "invalid stream: stream IDs must be less than 2,147,483,647"
                    )
        if len(payload)>frame_size:
            raise PayloadOverflow(
                    f"MAX_FRAME_SIZE exceeded"
                    )
        self.type=type
        self.payload=payload
        self.flags=flags
        self.streamid=streamid
    def tobytes(self):
        rio = io.BytesIO()
        pl= len(self.payload)
        rio.write(struct.pack(">I",pl)[2:])
        rio.write(struct.pack("B",self.type))
        rio.write(struct.pack("B",self.flags))
        rio.write(struct.pack("I",self.streamid))
        rio.write(self.payload)
        return rio.getvalue()
class SettingsFrame(HTTP2Frame):
    def __init__(self,header_table_size=4096,enable_push=True,max_concurrent_streams=255,initial_window_size=65535,max_frame_size=16384,ack=False):
        self.header_table_size,self.enable_push,self.max_concurrent_streams,self.initial_window_size,self.max_frame_size = header_table_size,enable_push,max_concurrent_streams,initial_window_size,max_frame_size
        self.payload=self._generate_payload() if not ack else ""
        self.flags=0x80 if ack else 0
        self.type=0x4
        super().__init__(self.type,self.payload,self.flags,0x00,max_frame_size)
    def _generate_payload(self):
        result=[]
        for index,value in enumerate([self.header_table_size,self.enable_push,self.max_concurrent_streams,self.initial_window_size,self.max_frame_size]):
            result.append(struct.pack("H",index))
            result.append(struct.pack("I",int(value)))
        return b''.join(result)

        
