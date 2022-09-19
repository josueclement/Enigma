from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Hash import SHA512


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
    with open('sha512.dat', 'wb') as sha512_dat:
        write_l(sha512_dat, 100)
        
        for i in range(100):
            data = get_random_bytes(i)
            write_lv(sha512_dat, data)

            sha512 = SHA512.new(data)
            hash = sha512.digest().hex()
            write_lv(sha512_dat, hash.encode('ascii'))

    with open('sha512.dat', 'rb') as sha512_dat:
        data = sha512_dat.read()
        sha512 = SHA512.new(data)
    
    with open('sha512.dat.txt', 'w') as sha512_dat_txt:
        sha512_dat_txt.write(sha512.hexdigest())
    

if __name__ == '__main__':
    main()
