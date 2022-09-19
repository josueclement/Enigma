from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from base64 import b64encode


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
    with open('b64.dat', 'wb') as b64_dat:
        write_l(b64_dat, 100)

        for i in range(1, 101):
            data = get_random_bytes(i)
            write_lv(b64_dat, data)
            write_lv(b64_dat, b64encode(data))


if __name__ == '__main__':
    main()
