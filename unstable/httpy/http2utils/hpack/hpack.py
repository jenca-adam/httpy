from huffman import encode_dt,decode_dt
from integer import encode_int,decode_int
NEVER = 0
NO = 1
YES = 2 
class Encoder:
    def 
    def _encode_indexed_header_field(self):
        r=encode_int(self.index,7)
        r[0]|=128
        return r
    def _encode_literal_header_field(self,name,add


