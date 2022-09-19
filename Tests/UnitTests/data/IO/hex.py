from Crypto.Random import get_random_bytes
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
    with open('hex.dat', 'wb') as hex_dat:
        write_l(hex_dat, 100)

        for i in range(1, 101):
            data = get_random_bytes(i)
            write_lv(hex_dat, data)
            write_lv(hex_dat, data.hex().encode('ascii'))


if __name__ == '__main__':
    main()
