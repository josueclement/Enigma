from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1


def read_lv(stream: BinaryIO):
    data_len = stream.read(4)
    value_len = unpack('i', data_len)[0]
    return stream.read(value_len)


def write_lv(stream: BinaryIO, value: bytes):
    data_len = pack('i', len(value))
    stream.write(data_len)
    stream.write(value)


def write_l(stream: BinaryIO, value: int):
    data_len = pack('i', value)
    stream.write(data_len)


def main():
    with open('pbkdf2.dat', 'wb') as pbkdf2_dat:
        write_l(pbkdf2_dat, 10)

        for i in range(10):
            password = get_random_bytes(8).hex()
            salt = get_random_bytes(16)
            key = PBKDF2(password, salt, 32, count=50000, hmac_hash_module=SHA1)
            write_lv(pbkdf2_dat, password.encode('ascii'))
            write_lv(pbkdf2_dat, salt)
            write_lv(pbkdf2_dat, key)


if __name__ == '__main__':
    main()
