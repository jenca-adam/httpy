import socket
import ssl
import frame
import settings
import stream
from error import *
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
def start_connection(host,port,client_settings,alpn=True):
    context = ssl.create_default_context()
    if alpn:
        context.set_alpn_protocols(["h2"])
    sock=context.wrap_socket(socket.create_connection((host,port)),server_hostname=host)
    if sock.selected_alpn_protocol()!="h2":
        return False,sock,None
    sf=sock.makefile("b")
    sock.send(PREFACE)
    server_settings=settings.Settings(frame.parse(sf).dict)
    sock.send(frame.SettingsFrame(ack=True).tobytes())
    sock.send(frame.SettingsFrame(**client_settings.settings).tobytes()) 
    return True,sock,server_settings
class Streams:

    def __init__(self,max_concurrent_streams,conn):
        self.max_concurrent_streams=max_concurrent_streams
        self.streams=[]
        self.inbound=[]
        self.conn=conn
        self.outbound=[]
    def add_stream(self,stream):
        if stream.streamid%2:
            self.outbound.append(stream)
        else:
            self.inbound.append(stream)
        self.streams.append(stream)
    def __getitem__(self,streamid):
        for s in self.streams:
            if s.streamid==streamid:
                return stream
        s=stream.Stream(streamid,self.conn)
        self.add_stream(s)
        return s
class Connection:
    def __init__(self,host,port,client_settings={}):
        self.host=host
        self.port=port
        self.settings=settings.Settings(client_settings)
        self.streams=Streams()
        self.highest_id=-1
    def create_stream(self):
        new_stream_id=self.highest_id+2
        self.highest_id+=2
        s=Stream(new_stream_id,self)
        self.streams.add_stream(s)
        return s

    def start(self):
        success,self.socket,self.server_settings=start_connection(self.host,self.port,self.settings)
        if not success:
            return False,self.socket
        self.settings=self.merge_settings(self.server_settings,self.settings)
        return True,self.socket
    def send_frame(self,frame):
        self.socket.send(frame.tobytes())
    def loop(self):
        self.sockfile=self.socket.makefile("b")
        while True:
            nextframe=frame.parse(self.sockfile)
            frame_stream=self.streams[nextframe.streamid]
            frame_stream.process(nextframe)
        
