from httpy import ProtoVersion
from . import frames
class HTTP2Sender:
    def __init__(self,method,headers,body,path,authority,debug):
        self.method=method
        self.path=path
        self.authority=authority
        self.body=body
        self.headers=headers
        self.headers.update({":path":path,":method":method,":authority",authority})
        self.frames = 
