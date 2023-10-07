#!/usr/bin/env python3
import frame
import os
import random
import error
import timeit

print("-FRAME TESTING-")
print("0: Data frame")
print("\ta) no padding ok")
e = os.urandom(random.randrange(200))
d = frame.DataFrame(e, streamid=0x420)
h = frame.parse(d._toio())
print(h.__dict__, d.__dict__)
assert h.__dict__ == d.__dict__
print("ok")
print("\tb) padding ok")
pad = random.randrange(1, 256)
e = os.urandom(random.randrange(200))
d = frame.DataFrame(e, padding=pad, streamid=0x69420)
h = frame.parse(d._toio())
assert h.__dict__ == d.__dict__
print("ok")
print("\tc) no stream id fail")
try:
    s = False
    g = frame.DataFrame(b"")
    frame.parse(g._toio())
except error.PROTOCOL_ERROR:
    s = True
assert s
print("ok")
print("\td) nonzero padding fail")
try:
    s = False
    g = frame.DataFrame(b"", streamid=0x9, padding=69)
    g.payload = g.payload[:-1] + b"\x45"
    frame.parse(g._toio())
except error.PROTOCOL_ERROR:
    s = True
assert s
print("ok")
print("1: Headers frame")
print("\ta) eq?")
e = os.urandom(random.randrange(200))

d = frame.HeadersFrame(
    e,
    streamid=0x420,
    priority_weight=42,
    stream_dependency=frame.StreamDependency(25, bool(random.randrange(2))),
    end_headers=bool(random.randrange(2)),
    end_stream=bool(random.randrange(2)),
    pad_length=random.randrange(1, 256),
)
h = frame.parse(d._toio())
assert h.__dict__ == d.__dict__
print("2:Priority Frame")
d = frame.PriorityFrame(
    priority_weight=random.randrange(1, 256),
    stream_dependency=frame.StreamDependency(
        random.randrange(0, 2**31 - 1), bool(random.randrange(2))
    ),
    streamid=0x129,
)
h = frame.parse(d._toio())
assert h.__dict__ == d.__dict__
print("ok")
print("3:RstStream Frame")
d = frame.RstStreamFrame(random.randrange(0x420))
h = frame.parse(d._toio())
assert d.__dict__ == h.__dict__
print("ok")
print("4:Settings Frame")
print("\ta) normal")
d = frame.SettingsFrame(
    header_table_size=random.randrange(2**32),
    enable_push=bool(random.randrange(2)),
    max_concurrent_streams=random.randrange(2**32),
    initial_window_size=random.randrange(0x7FFFFFFF + 1),
    max_frame_size=random.randrange(0x4000, 0x1000000),
    max_header_list_size=random.randrange(2**32),
    ack=False,
)
h = frame.parse(d._toio())
print(d.__dict__, h.__dict__)
assert d.__dict__ == h.__dict__
