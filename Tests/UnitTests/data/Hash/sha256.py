from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Hash import SHA256


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
    with open('sha256.dat', 'wb') as sha256_dat:
        write_l(sha256_dat, 100)
        
        for i in range(100):
            data = get_random_bytes(i)
            write_lv(sha256_dat, data)

            sha256 = SHA256.new(data)
            hash = sha256.digest().hex()
            write_lv(sha256_dat, hash.encode('ascii'))

    with open('sha256.dat', 'rb') as sha256_dat:
        data = sha256_dat.read()
        sha256 = SHA256.new(data)
    
    with open('sha256.dat.txt', 'w') as sha256_dat_txt:
        sha256_dat_txt.write(sha256.hexdigest())
    

if __name__ == '__main__':
    main()
