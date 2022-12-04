import math
def encode_int(i,n=8):
    f=0b00000000
    b=bytearray()
    if i<2**n-1:
        f=f|i
    else:
        f=f|2**n-1
        i=i-(2**n-1)
        while i>128:
            b.append(128+i%128)
            print(i)
            i//=128

        b.append(i)
    t=b.copy()
    t.insert(0,f)
    return f,b,t
def decode_int(b,n=8,sp=0):
    prefix = nextnbits(b,n,sp)
    if prefix<2**n-1:
        print('sus')
        return prefix
    ix=math.ceil(n/8) # TODO: FIX DIS! 
    m=0
    for o in  b[ix:]:
        prefix+=(o&127)*2**(m)
        if o&128!=128: # fst bit 1
            break
        m+=7
    return prefix
        
    

