from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20
from struct import pack, unpack
from typing import BinaryIO


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
    with open('salsa20.dat', 'wb') as salsa20_data_dat:
        write_l(salsa20_data_dat, 50)

        for i in range(1, 101):
            key = get_random_bytes(32)
            write_lv(salsa20_data_dat, key)
            iv = get_random_bytes(8)
            write_lv(salsa20_data_dat, iv)
            data = get_random_bytes(i * 16)
            write_lv(salsa20_data_dat, data)

            cipher = Salsa20.new(key=key, nonce=iv)
            enc = cipher.encrypt(data)
            write_lv(salsa20_data_dat, enc)


if __name__ == '__main__':
    main()
