from abc import ABC, abstractmethod
from binascii import hexlify
from struct import pack
from typing import Tuple

from oracle import Oracle

BLOCKSIZE = 16  # bytes


class Forger(ABC):
    @abstractmethod
    def generate_inputs(self) -> Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def generate_forgery(self, m: bytes, c: bytes) -> Tuple[bytes, bytes]:
        pass

    def forge_tag(self):
        m, a = self.generate_inputs()
        print(f'Generated chosen plaintext:\n{hexlify(m)}\n')

        oracle = Oracle()
        t, c = oracle.encrypt(m, a)
        print(
            f'Encryption Oracle returned -\n'
            f'Ciphertext: {hexlify(c)}\n'
            f'Tag: {hexlify(t)}\n'
        )

        t_, c_ = self.generate_forgery(m, c)
        print(
            f'Forgery -\n'
            f'Ciphertext: {hexlify(c_)}\n'
            f'Tag: {hexlify(t_)}\n'
        )

        valid, _ = oracle.decrypt(a, c_, t_)
        print(f'Forged tag is valid: {valid}')
    

def encode_length(datalen: int) -> bytes:
    encoded = b''
    while datalen > 0:
        encoded += pack('B', datalen % 0x100)
        datalen //= 0x100
    return b'\x00' * (BLOCKSIZE - len(encoded)) + encoded


def xor(buf1: bytes, buf2: bytes) -> bytes:
    return bytes([b1 ^ b2 for (b1, b2) in zip(buf1, buf2)])
