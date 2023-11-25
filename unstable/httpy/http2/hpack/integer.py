def encode_int(i, n=7, return_int=False):
    mbits = 2**n - 1
    if i < mbits:
        if return_int:
            return i
        return bytearray([i])
    else:
        bts = [mbits]
        i -= mbits
        while i >= 128:
            bts.append(128 + (i & 127))
            i >>= 7
        bts.append(i)
    if return_int:
        return int.from_bytes(bytes(bytearray(bts)), "big")
    return bytearray(bts)


def decode_int(barr, n=7):
    b = iter(barr)
    num = next(b) & 0xFF >> (8 - n)
    mbits = 2**n - 1
    index = 0
    if num == mbits:
        for index, byte in enumerate(b):
            if byte >= 128:
                num += (byte - 128) << index * 7
            else:
                num += byte << index * 7
                break
        else:
            # Not Needed
            pass
    return num, index + 1
