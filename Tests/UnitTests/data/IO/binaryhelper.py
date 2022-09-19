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
    with open('binaryhelper.dat', 'wb') as bh_dat:
        bh_dat.write(pack('c', b'\xfe'))
        bh_dat.write(pack('?', True))
        bh_dat.write(pack('h', -12))
        bh_dat.write(pack('H', 12))
        bh_dat.write(pack('i', -120))
        bh_dat.write(pack('I', 120))
        bh_dat.write(pack('q', -1200))
        bh_dat.write(pack('Q', 1200))
        bh_dat.write(pack('f', 12.0))
        bh_dat.write(pack('d', 120.0))


if __name__ == '__main__':
    main()
