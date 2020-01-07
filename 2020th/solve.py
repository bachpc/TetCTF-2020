#!/usr/bin/env python

from pwn import *
import random
import time

r = remote("207.148.119.58", 6666)

def unshiftRight(x, shift):
    res = x
    for i in range(32):
        res = x ^ res >> shift
    return res

def unshiftLeft(x, shift, mask):
    res = x
    for i in range(32):
        res = x ^ (res << shift & mask)
    return res

def untemper(v):
    """ Reverses the tempering which is applied to outputs of MT19937 """

    v = unshiftRight(v, 18)
    v = unshiftLeft(v, 15, 0xefc60000)
    v = unshiftLeft(v, 7, 0x9d2c5680)
    v = unshiftRight(v, 11)
    return v

def temper(y):
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & (0x9d2c5680))
    y = y ^ ((y << 15) & (0xefc60000))
    y = y ^ (y >> 18)
    return y

def solve(a, b):
    res = []
    mt_i1, mt_i397 = untemper(a), untemper(b)
    for msb in range(2):
        y = (msb * 0x80000000) + (mt_i1 & 0x7fffffff)
        mt_i = mt_i397 ^ (y >> 1)
        if (y % 2) != 0:
            mt_i = mt_i ^ 0x9908b0df
        res.append(temper(mt_i))
    return res

# test = []
# for i in range(2025):
#     r = random.getrandbits(32)
#     test.append(r)

# print solve(test[1396], test[1792])
# print test[2019]

r.sendline("1396")
r.sendline("1792")
aa = []
for _ in range(2019):
    a = r.recvline().strip()
    if "Nope" not in a:
        aa.append(int(a))
res = solve(*aa)
r.sendline(str(solve(*aa)[0]))
r.interactive()
