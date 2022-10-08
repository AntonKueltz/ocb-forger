from os import urandom
from typing import Tuple

from common import Forger, encode_length, xor

BLOCKSIZE = 16  # bytes


class MinimalForger(Forger):
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        m = encode_length(BLOCKSIZE * 8) + urandom(BLOCKSIZE)
        return m, b''

    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        c_ = xor(c[:BLOCKSIZE], encode_length(BLOCKSIZE * 8))
        t_ = xor(m[BLOCKSIZE:], c[BLOCKSIZE:])
        return t_, c_


if __name__ == '__main__':
    forger = MinimalForger()
    forger.forge_tag()
