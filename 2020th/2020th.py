#!/usr/bin/env python3
import random

if __name__ == '__main__':
    nIndices = 2
    indices = [int(input()) for _ in range(nIndices)]

    for i in range(2019):
        r = random.getrandbits(32)
        print(r if i in indices else 'Nope!')

    # please guess the 2020th number!
    if int(input()) == random.getrandbits(32):
        print(open('flag.txt').read())
