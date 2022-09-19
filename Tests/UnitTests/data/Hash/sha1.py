from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
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
    with open('sha1.dat', 'wb') as sha1_dat:
        write_l(sha1_dat, 100)
        
        for i in range(100):
            data = get_random_bytes(i)
            write_lv(sha1_dat, data)

            sha1 = SHA1.new(data)
            hash = sha1.digest().hex()
            write_lv(sha1_dat, hash.encode('ascii'))

    with open('sha1.dat', 'rb') as sha1_dat:
        data = sha1_dat.read()
        sha1 = SHA1.new(data)
    
    with open('sha1.dat.txt', 'w') as sha1_dat_txt:
        sha1_dat_txt.write(sha1.hexdigest())
    

if __name__ == '__main__':
    main()
