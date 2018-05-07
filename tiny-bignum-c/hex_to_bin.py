import sys
if len(sys.argv) < 2:
    print("no input")
    exit()

s = sys.argv[1]
f = open("cipher", "wb")
from binascii import unhexlify
x = int(s, 16)
b = x.to_bytes(256, 'big')
f.write(b)
f.close()
