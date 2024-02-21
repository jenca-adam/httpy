from .huffman import encode_huffman, decode_huffman
from .integer import encode_int, decode_int
from .const import YES, NO, NEVER
from .table import Table, Entry
from httpy.utils import force_bytes
from .utils.stream_iterable import StreamIterable
import io


def _mkbytes(*parts):
    return b"".join(map(force_bytes, parts))


def _encode_string(string, huffman=True):
    if huffman:
        string = encode_huffman(string)
    l = encode_int(len(string))
    l[0] |= 0x80 if huffman else 0
    return _mkbytes(l, string)


def _decode_string(si):
    fb = si.read_back(1)
    huffman = fb & 0x80
    leng, _ = decode_int(si, 7)
    rest = si.read(leng)
    if huffman:
        return decode_huffman(rest).decode("utf-8")
    return rest.decode("utf-8")


def _mk_si(stream):
    si = StreamIterable(stream)
    return map(ord, si), si


class Encoder:
    """
    A HPACK encoder
    """

    def __init__(self):
        self.table = Table()

    def encode_headers(self, headers, huffman=True):
        """
        Encodes multiple headers with the current table
        """
        if isinstance(headers, dict):
            headers = headers.items()
        headers = sorted(
            headers, key=lambda a: not a[0].startswith(":")
        )  # Put pseudo-header fields first
        result = [self.encode_header(header, huffman) for header in headers]
        return b"".join(result)

    def encode_header(self, header, huffman=True):
        """
        Encodes a single header with the current table
        """
        name, value, *index_mode = header
        if not index_mode:  # Default
            index_mode = YES
        else:
            index_mode, *_ = index_mode
        entry = Entry(name, value)
        complete_match_index = self.table.find_item(entry)
        if complete_match_index:  # already in the table, no need to add
            return self._encode_indexed_header_field(complete_match_index)
        res = self._encode_literal_header_field(name, value, index_mode, huffman)

        if index_mode == YES:
            self.table.add(entry)
        return res

    def _encode_indexed_header_field(self, index):
        r = encode_int(index, 7)
        r[0] |= 0x80
        return r

    def _encode_literal_header_field(self, name, value, index_mode=YES, huffman=True):
        if index_mode == YES:
            mask = 0x40  # 01
            prefix = 6
        elif index_mode == NO:
            mask = 0x0  # 0000
            prefix = 4
        elif index_mode == NEVER:
            mask = 0x10  # 0001
            prefix = 4
        else:
            raise ValueError(
                f"Wrong index mode {index_mode}! Must be hpack.YES, hpack.NO  or hpack.NEVER"
            )
        table_index = self.table.find_item(name)
        if table_index is not None:
            # indexed name
            name_part = encode_int(table_index, prefix)

        else:
            name_part = bytearray([0, *_encode_string(name, huffman)])
        name_part[0] |= mask
        value_part = _encode_string(value, huffman)
        return _mkbytes(name_part, value_part)


class Decoder:
    """
    A HPACK decoder
    """

    def __init__(self):
        self.table = Table()

    def _decode_indexed_header_field(self, first, si):
        index, c = decode_int(si, 7)
        return self.table[index], NO

    def _decode_literal_header_field(self, first, si):
        if first & 0x40:
            index_mode = YES
            prefix = 6

        elif first & 0x10:
            index_mode = NEVER
            prefix = 4
        else:
            index_mode = NO
            prefix = 4
        name_index, _ = decode_int(si, prefix)
        if name_index > 0:
            name = self.table[name_index].name
        else:
            name = _decode_string(si)
        value = _decode_string(si)
        return Entry(name, value), index_mode

    def _decode_header(self, first, si):
        if first & 0x80:
            entry, index = self._decode_indexed_header_field(first, si)
        else:
            entry, index = self._decode_literal_header_field(first, si)
        if index == YES:
            self.table.add(entry)
        return (entry.name, entry.value)

    def decode_headers(self, b):
        """
        Decodes multiple headers with the current dynamic table
        """
        si = StreamIterable(io.BytesIO(b), func=ord)
        headers_list = []
        while True:
            first = si.get_next()
            if first is None:
                break
            headers_list.append(self._decode_header(first, si))
        return dict(headers_list)


class HPACK(Encoder, Decoder):
    """
    A HPACK encoder/decoder pair with a shared dynamic table
    """

    def __init__(self):
        self.table = Table()
