from os import urandom
from random import randint
from typing import Tuple

from common import Forger, encode_length, xor

BLOCKSIZE = 16  # bytes


class LongerForger(Forger):
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        self.blocks = randint(2, 10)  # choose random amount of multiple blocks
        m = urandom(BLOCKSIZE * self.blocks)
        m += encode_length(BLOCKSIZE * 8)  # bits
        m += urandom(BLOCKSIZE)
        return m, b''
    
    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        c_ = c[:self.blocks * BLOCKSIZE]

        last_block = b'\x00' * BLOCKSIZE
        for i in range(self.blocks):
            m_i = m[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
            last_block = xor(last_block, m_i)
        c_m1 = c[self.blocks * BLOCKSIZE:(self.blocks + 1) * BLOCKSIZE]
        last_block = xor(last_block, c_m1)
        last_block = xor(last_block, encode_length(BLOCKSIZE * 8))  # bits

        c_ += last_block

        m_m = m[(self.blocks + 1) * BLOCKSIZE:]
        c_m = c[(self.blocks + 1) * BLOCKSIZE:]
        t_ = xor(m_m, c_m)

        return t_, c_


if __name__ == '__main__':
    forger = LongerForger()
    forger.forge_tag()
