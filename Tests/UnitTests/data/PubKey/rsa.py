from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def save_private_key_to_pem(key: RSA,
                            output_stream: BinaryIO,
                            password: str,
                            protection: str = 'PBKDF2WithHMAC-SHA1AndAES256-CBC') -> None:
    """Save private RSA key
    :param key: RSA key
    :param output_stream: Output stream
    :param password: Password
    :param protection: Protection algorithm
    """
    encrypted_key = key.export_key(passphrase=password, pkcs=8, protection=protection)
    output_stream.write(encrypted_key)


def save_public_key_to_pem(key: RSA,
                           output_stream: BinaryIO) -> None:
    """Save public RSA key
    :param key: RSA key
    :param output_stream: Output stream
    """
    key_content = key.publickey().export_key()
    output_stream.write(key_content)


def encrypt(key: RSA,
            data: bytes) -> bytes:
    """Encrypt data with RSA key
    :param key: RSA key
    :param data: Data to encrypt
    :return: Encrypted data
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)


def decrypt(key: RSA,
            data: bytes) -> bytes:
    """Decrypt data with RSA key
    :param key: RSA key
    :param data: Data to decrypt
    :return: Decrypted data
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(data)


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
    rsa_key1 = RSA.generate(4096)
    rsa_key2 = RSA.generate(4096)

    with open('pub_key1.pem', 'wb') as pub_pem1:
        save_public_key_to_pem(rsa_key1, pub_pem1)

    with open('pk_key1.pem', 'wb') as pk_pem1:
        save_private_key_to_pem(rsa_key1, pk_pem1, 'test1234')

    with open('pub_key2.pem', 'wb') as pub_pem2:
        save_public_key_to_pem(rsa_key2, pub_pem2)

    with open('pk_key2.pem', 'wb') as pk_pem2:
        save_private_key_to_pem(rsa_key2, pk_pem2, None, None)

    with open('rsa1.dat', 'wb') as rsa_dat:
        write_l(rsa_dat, 10)

        for i in range(1, 11):
            data = get_random_bytes(i * 16)
            enc = encrypt(rsa_key1, data)
            write_lv(rsa_dat, data)
            write_lv(rsa_dat, enc)

    with open('rsa2.dat', 'wb') as rsa_dat:
        write_l(rsa_dat, 10)

        for i in range(1, 11):
            data = get_random_bytes(i * 16)
            enc = encrypt(rsa_key2, data)
            write_lv(rsa_dat, data)
            write_lv(rsa_dat, enc)


if __name__ == '__main__':
    main()
