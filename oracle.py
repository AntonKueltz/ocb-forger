from os import urandom
from typing import Tuple

from ocb.aes import AES
from ocb import OCB

BLOCKSIZE = 16  # bytes


class Oracle:
    def __init__(self):
        self.n = urandom(BLOCKSIZE)
        self.k = urandom(BLOCKSIZE)

        aes = AES(BLOCKSIZE * 8)  # to bits
        self.ocb = OCB(aes)

    def encrypt(self, m: bytes, a: bytes) -> Tuple[bytes, bytes]:
        self.ocb.setKey(self.k)
        self.ocb.setNonce(self.n)
        return self.ocb.encrypt(m, a)

    def decrypt(self, a: bytes, c: bytes, t: bytes) -> Tuple[bool, bytes]:
        self.ocb.setKey(self.k)
        self.ocb.setNonce(self.n)
        return self.ocb.decrypt(a, c, t)
