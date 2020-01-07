#!/usr/bin/env python3
from Crypto.Cipher import AES
import os, json

PAD = bytes.fromhex("2019") * 8


def pad(s):
    pad_length = 16 - len(s) % 16
    return bytes([pad_length]) + PAD[:pad_length - 1] + s


def unpad(s):
    pad_length = s[0]
    if (
            len(s) % 16 != 0 or
            not 1 <= pad_length <= 16 or
            s[1:pad_length] != PAD[:pad_length - 1]
    ):
        raise Exception("incorrect padding")

    return s[pad_length:]


def encrypt(key, plaintext):
    aes = AES.new(key, AES.MODE_CBC, os.urandom(16))
    return aes.IV + aes.encrypt(pad(plaintext))


def decrypt(key, ciphertext):
    aes = AES.new(key, AES.MODE_CBC, ciphertext[:16])
    return unpad(aes.decrypt(ciphertext[16:]))


if __name__ == '__main__':
    key = os.urandom(16)
    obj = {'admin': False, 'flag': open("flag1.txt").read()}
    token = encrypt(key, json.dumps(obj).encode())

    # please decrypt the token!
    print(token.hex())

    for _ in range(65536):
        try:
            token = bytes.fromhex(input())
            obj = json.loads(decrypt(key, token))

            # can you also forge arbitrary tokens?
            if obj['admin']:
                print(open("flag2.txt").read())

        except Exception as e:
            print(e)
