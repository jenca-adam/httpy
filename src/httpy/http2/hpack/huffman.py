from .static import HUFFMAN_TABLE, HUFFMAN_TABLE_DICT
from .errors import *
from .utils.bitarray import bytes2bits
from httpy.utils import force_bytes
import io


def encode_huffman(inp):
    """
    Encodes a byte sequence using Huffman encoding with the HPACK Huffman table
    """
    if not isinstance(inp, bytes):
        inp = force_bytes(inp)
        # warn! TODO

        # raise HuffmanEncodingError("Can only encode bytes using huffman encoding")
    result = 0
    total_size = 0
    for byte in inp:
        add, size = HUFFMAN_TABLE[byte]
        result <<= size
        result |= add & (2 ** (size + 1) - 1)
        total_size += size
    # pad with 1s
    padding_size = (8 - (total_size % 8)) % 8
    result <<= padding_size
    result |= (1 << padding_size) - 1
    return int.to_bytes(result, (total_size + padding_size) // 8, "big")


def decode_huffman(inp):
    """
    Decodes a Huffman-encoded byte sequence with the HPACK Huffman table
    """
    nbits = len(inp) * 8  # huffman strings are padded with 1s to nearest octet
    bits = bytes2bits(inp, "big", nbits)
    stream = io.StringIO(bits)
    current = ""
    total = bytearray()
    # Because of the structure of the Huffman table, padded 1s will be ignored at the end of the cycle
    while True:
        next_bit = stream.read(1)
        if not next_bit:
            break
        current += next_bit
        if current in HUFFMAN_TABLE_DICT:
            if HUFFMAN_TABLE_DICT[current] > 255:  # EOS
                break
            total.append(HUFFMAN_TABLE_DICT[current])
            current = ""
    return bytes(total)
