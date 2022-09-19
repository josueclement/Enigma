from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Hash import MD5


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
    with open('md5.dat', 'wb') as md5_dat:
        write_l(md5_dat, 100)
        
        for i in range(100):
            data = get_random_bytes(i)
            write_lv(md5_dat, data)

            md5 = MD5.new(data)
            hash = md5.digest().hex()
            write_lv(md5_dat, hash.encode('ascii'))

    with open('md5.dat', 'rb') as md5_dat:
        data = md5_dat.read()
        md5 = MD5.new(data)
    
    with open('md5.dat.txt', 'w') as md5_dat_txt:
        md5_dat_txt.write(md5.hexdigest())
    

if __name__ == '__main__':
    main()
