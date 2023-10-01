import math
import io
def bits2bytes(bits,endian="big"):
    return int(bits,2).to_bytes(math.ceil(len(bits)/8),endian)
def bytes2bits(bytes,endian="big",nbits=None):
    bits = bin(int.from_bytes(bytes,endian))[2:]
    if nbits is not None:
        bits = "0"*(nbits-len(bits))+bits
    return bits
# Zombie code
"""
def bits2bytes_align(bits):
    barr=bytearray()
    buff=io.StringIO(bits)
    while True:
        next=buff.read(8)
        if not next:
            break
        elif len(next)<8:
            barr.append(int(next,2)<<(8-len(next)))
            break
        else:
            barr.append(int(next,2))
    return barr"""
