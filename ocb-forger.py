from binascii import hexlify
from os import urandom
from struct import pack
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


def encode_length(datalen: int) -> bytes:
    encoded = b''
    while datalen > 0:
        encoded += pack('B', datalen % 0x100)
        datalen //= 0x100
    return b'\x00' * (BLOCKSIZE - len(encoded)) + encoded


def generate_inputs() -> Tuple[bytes, bytes]:
    m = encode_length(BLOCKSIZE * 8) + urandom(BLOCKSIZE)
    return m, b''


def xor(buf1: bytes, buf2: bytes) -> bytes:
    return bytes([b1 ^ b2 for (b1, b2) in zip(buf1, buf2)])


def generate_forgery(m: bytes, c: bytes) -> Tuple[bytes, bytes]:
    c_ = xor(c[:BLOCKSIZE], encode_length(BLOCKSIZE * 8))
    t_ = xor(m[BLOCKSIZE:], c[BLOCKSIZE:])
    return t_, c_


def forge_tag():
    m, a = generate_inputs()
    print(f'Generated chosen plaintext:\n{hexlify(m)}\n')

    oracle = Oracle()
    t, c = oracle.encrypt(m, a)
    print(
        f'Encryption Oracle returned -\n'
        f'Ciphertext: {hexlify(c)}\n'
        f'Tag: {hexlify(t)}\n'
    )

    t_, c_ = generate_forgery(m, c)
    print(
        f'Forgery -\n'
        f'Ciphertext: {hexlify(c_)}\n'
        f'Tag: {hexlify(t_)}\n'
    )

    valid, m_ = oracle.decrypt(a, c_, t_)
    print(f'Forged tag is valid: {valid}')


if __name__ == '__main__':
    forge_tag()