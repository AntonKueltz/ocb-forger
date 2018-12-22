from binascii import hexlify
from os import urandom
from struct import pack

from ocb.aes import AES  # pip install pyocb
from ocb import OCB

BLOCKSIZE = 16  # cipher block size in bytes


def xor(lbytes, rbytes):
    result = b''
    for lb, rb in zip(lbytes, rbytes):
        result += pack('B', lb ^ rb)
    return result


def encode_length(datalen):
    encoded = b''
    while datalen > 0:
        encoded += pack('B', datalen % 0x100)
        datalen //= 0x100
    return b'\x00' * (BLOCKSIZE - len(encoded)) + encoded


def forge_tag():
    ptxt = encode_length(BLOCKSIZE * 8) + urandom(BLOCKSIZE)
    nonce = urandom(BLOCKSIZE)
    key = urandom(BLOCKSIZE)
    print('Generated chosen plaintext:\n{}\n'.format(
        hexlify(ptxt)))

    aes = AES(128)
    ocb = OCB(aes)
    ocb.setNonce(nonce)
    ocb.setKey(key)
    tag, ctxt = ocb.encrypt(ptxt, b'')  # encryption oracle
    print('Encryption Oracle returned -\nCiphertext: {}\nTag: {}\n'.format(
        hexlify(ctxt), hexlify(tag)))

    c1 = ctxt[:16]
    ctxt_ = xor(c1, encode_length(128))

    c2 = ctxt[16:]
    m2 = ptxt[16:]
    tag_ = xor(m2, c2)
    print('Forgery -\nCiphertext: {}\nTag: {}\n'.format(
        hexlify(ctxt_), hexlify(tag_)))

    ocb.setNonce(nonce)
    ocb.setKey(key)
    valid, ptxt = ocb.decrypt(b'', ctxt_, tag_)  # decryption oracle
    print('Forged tag is valid: {}'.format(valid))


if __name__ == '__main__':
    forge_tag()
