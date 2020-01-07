#!/usr/bin/sage

###############################################################################
# I don't ask you for the backdoor. I just wonder whether it exists or not.   #
# If you know the backdoor, please go on and get the flag!                    #
###############################################################################

from sage.all import EllipticCurve, GF, Zmod, ZZ
import socketserver
import os
import signal
from Crypto.Util.number import bytes_to_long
from hashlib import sha256

# Dual_EC_Drbg parameters taken from:
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90a.pdf
# Section A.1.1
EC = EllipticCurve(
    GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff),
    [-3, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b]
)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
assert EC.cardinality() == n
Zn = Zmod(n)
G = EC((0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))
P = G
Q = EC((0xc97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192,
        0xb28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046))


class DualEcDrbg(object):
    """
    Dual Elliptic Curve Deterministic Random Bit Generator
    """

    def __init__(self, seed):
        self.s = ZZ(bytes_to_long(seed))

    def next_bits(self):
        """
        Transit to the next state and output 240 bits as specified in the
        document above.
        """
        self.s = ZZ((self.s * P)[0])
        return ZZ((self.s * Q)[0]) & (2 ** 240 - 1)


def sign(private_key, message, rand):
    """
    Implementation of ECDSA signature generation algorithm.

    Arguments:
        private_key: an element of Zn
        message: a byte array/string
        rand: should be an instance of DualEcDrbg

    Output:
        a pair of elements of Zn as signature
    """
    z = Zn(ZZ(sha256(message).hexdigest(), 16))
    k = Zn(rand.next_bits())
    assert k != 0
    K = ZZ(k) * G
    r = Zn(K[0])
    assert r != 0
    s = (z + r * private_key) / k
    assert s != 0
    return r, s


def verify(public_key, message, signature):
    """
    Implementation of ECDSA signature verification algorithm.

    Arguments:
        public_key: a point on curve
        message: a byte array/string
        signature: a pair of elements of Zn

    Output:
        None if the signature is correct, otherwise raise an AssertionError
    """
    r, s = map(Zn, signature)
    assert r != 0,          "Incorrect signature"
    assert s != 0,          "Incorrect signature"
    z = Zn(ZZ(sha256(message).hexdigest(), 16))
    u1, u2 = z / s, r / s
    K = ZZ(u1) * G + ZZ(u2) * public_key
    assert K != 0,          "Incorrect signature"
    assert Zn(K[0]) == r,   "Incorrect signature"


class Handler(socketserver.StreamRequestHandler):
    """
    The main handler.
    """

    def handle(self):
        print(self.client_address[0], "connected")  # logging

        rand = DualEcDrbg(os.urandom(16))
        msg = str(rand.next_bits()).encode()
        sig = sign(a, msg, rand)  # a is the imported private key
        self.wfile.write(msg + b'\n')
        self.wfile.write(str(sig).encode() + b'\n')

        try:
            msg2 = b"I am admin"
            signal.alarm(20)
            line = self.rfile.readline().strip().decode()
            if not line:  # empty input
                return

            print(self.client_address[0], line)  # logging
            sig2 = map(Zn, line.lstrip('(').rstrip(')').split(','))
            verify(A, msg2, sig2)  # A is the imported public key

        except Exception as e:
            print(self.client_address[0], e)  # logging
            self.wfile.write(str(e).encode() + b'\n')
            return

        # the signature is valid -> looks like the backdoor does exist!
        self.wfile.write(flag + b'\n')

        # logging
        print(self.client_address[0], "got FLAG!")


if __name__ == "__main__":
    from yaecc_secret import a, A, flag

    assert ZZ(a) * G == A
    with open("public_key.txt", "w") as f:
        f.write(str(A))

    HOST, PORT = "0.0.0.0", 5555  # maybe updated
    server = socketserver.ForkingTCPServer((HOST, PORT), Handler, False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()

    def timeout_handler(_, __):
        raise TimeoutError("Timeout!")
    signal.signal(signal.SIGALRM, timeout_handler)

    print("Serving at", HOST, PORT)
    server.serve_forever()
