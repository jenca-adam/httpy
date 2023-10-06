#!/usr/bin/env python3
import frame
import os
import random

print("-FRAME TESTING-")
print("0: Data frame")
print("\ta) no padding")
e = os.urandom(random.randrange(200))
d = frame.DataFrame(e)
h = frame.parse(d._toio())
assert h.payload == d.payload
assert h.data == d.data
print("ok")
