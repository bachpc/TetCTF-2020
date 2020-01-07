#!/usr/bin/env python

from pwn import *

r = remote("207.148.119.58", 5555)
token = r.recvline().strip().decode("hex")
iv, ct = token[:16], token[16:]
# print "len(ct) =", len(ct)

###### find len(padding)

# for i in range(0, 16):
#     tmp = list(iv)
#     tmp[i] = chr(ord(tmp[i])^1)
#     tmp = "".join(tmp)
#     aa = tmp + ct
#     r.sendline(aa.encode("hex"))
#     print r.recvline()

###### len(padding) = 2

# xx{"admin": fals|e, "flag": "TetC|TF{aaaaaaaaaaa"}

aaa = list(iv)
old = "fals"
new = " tru"
for i in range(4):
    aaa[12+i] = chr(ord(aaa[12+i]) ^ ord(old[i]) ^ ord(new[i]))
    bbb = "".join(aaa) + ct
r.sendline(bbb.encode("hex"))
print r.recvline()

# part 2 = th3_b3g1nn1ng_d03s_n0t_h3lp}

########################## part 1
import string
PAD = "\x20\x19" * 8
iv, ct = ct[16:32], ct[32:]
flag = "TF{"
sig = string.ascii_letters + string.digits + "}{_"
for i in range(3, 16, 1):
    aaa = list(iv)
    aaa[0] = chr(ord(aaa[0]) ^ (i+1) ^ ord("T"))
    for j in range(1, i, 1):
        aaa[j] = chr(ord(aaa[j]) ^ ord(flag[j]) ^ ord(PAD[j-1]))
    tmp = aaa[i]
    for j in sig:
        aaa[i] = chr(ord(tmp) ^ ord(j) ^ (ord(PAD[i-1])))
        bbb = "".join(aaa) + ct
        r.sendline(bbb.encode("hex"))
        if "padding" not in r.recvline():
            flag += j
            print flag
            break

print flag
# part 1 = TF{p4dd1ng_4t_
