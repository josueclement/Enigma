from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from struct import pack, unpack
from typing import BinaryIO, Any
from Crypto.PublicKey import RSA
from io import BytesIO
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA1


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


def encrypt_key_stream(input_stream: BinaryIO,
                       output_stream: BinaryIO,
                       rsa: RSA,
                       key_name: str) -> None:
    key = get_random_bytes(32)
    iv = get_random_bytes(16)

    with BytesIO() as ms:
        write_lv(ms, key)
        write_lv(ms, iv)
        ms.seek(0)
        key_data = ms.read()
    
    enc_key_data = encrypt(rsa, key_data)

    output_stream.write(b'AENCR!')
    output_stream.write(b'\x05')
    write_lv(output_stream, key_name.encode('ascii'))
    write_lv(output_stream, enc_key_data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypt_and_pad(input_stream, output_stream, cipher, 16)


def encrypt_pass_stream(input_stream: BinaryIO,
                        output_stream: BinaryIO,
                        password: str) -> None:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32, count=60000, hmac_hash_module=SHA1)
    iv = get_random_bytes(16)

    output_stream.write(b'AENCP!')
    output_stream.write(b'\x05')
    write_lv(output_stream, salt)
    write_lv(output_stream, iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypt_and_pad(input_stream, output_stream, cipher, 16)


def encrypt_and_pad(input_stream: BinaryIO,
                    output_stream: BinaryIO,
                    cipher: Any,
                    block_size: int,
                    padding: str='pkcs7'):
    pad_done = False
    buffer = None
    enc = None

    while True:
        buffer = input_stream.read(4096)

        if len(buffer) == 4096:
            enc = cipher.encrypt(buffer)
            output_stream.write(enc)
        elif len(buffer) > 0:
            pad_data = pad(buffer, block_size, padding)
            enc = cipher.encrypt(pad_data)
            output_stream.write(enc)
            pad_done = True
        
        if len(buffer) != 4096:
            break
    
    if not pad_done:
        pad_data = pad(b'', block_size, padding)
        enc = cipher.encrypt(pad_data)
        output_stream.write(enc)



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


def get_enc_data_key(data: bytes, rsa_key: RSA) -> bytes:
    with BytesIO(data) as input_stream,\
         BytesIO() as output_stream:
        encrypt_key_stream(input_stream, output_stream, rsa_key, 'rsa_key1')
        output_stream.seek(0)
        return output_stream.read()


def get_enc_data_pass(data: bytes, password: str) -> bytes:
    with BytesIO(data) as input_stream,\
         BytesIO() as output_stream:
        encrypt_pass_stream(input_stream, output_stream, password)
        output_stream.seek(0)
        return output_stream.read()


def main():

    password = 'test1234'
    rsa_key = RSA.generate(4096)

    with open('pub_key1.pem', 'wb') as pub_pem1:
        save_public_key_to_pem(rsa_key, pub_pem1)

    with open('pk_key1.pem', 'wb') as pk_pem1:
        save_private_key_to_pem(rsa_key, pk_pem1, 'test1234')

    with open('aesfileenc_key.dat', 'wb') as aes_key_dat:
        write_l(aes_key_dat, 5)

        data = get_random_bytes(1000)
        enc_data = get_enc_data_key(data, rsa_key)
        write_lv(aes_key_dat, data)
        write_lv(aes_key_dat, enc_data)

        data = get_random_bytes(4096)
        enc_data = get_enc_data_key(data, rsa_key)
        write_lv(aes_key_dat, data)
        write_lv(aes_key_dat, enc_data)
        
        data = get_random_bytes(6000)
        enc_data = get_enc_data_key(data, rsa_key)
        write_lv(aes_key_dat, data)
        write_lv(aes_key_dat, enc_data)

        data = get_random_bytes(8192)
        enc_data = get_enc_data_key(data, rsa_key)
        write_lv(aes_key_dat, data)
        write_lv(aes_key_dat, enc_data)

        data = get_random_bytes(10000)
        enc_data = get_enc_data_key(data, rsa_key)
        write_lv(aes_key_dat, data)
        write_lv(aes_key_dat, enc_data)

    with open('aesfileenc_pass.dat', 'wb') as aes_pass_dat:
        write_l(aes_pass_dat, 5)

        data = get_random_bytes(1000)
        enc_data = get_enc_data_pass(data, password)
        write_lv(aes_pass_dat, data)
        write_lv(aes_pass_dat, enc_data)

        data = get_random_bytes(4096)
        enc_data = get_enc_data_pass(data, password)
        write_lv(aes_pass_dat, data)
        write_lv(aes_pass_dat, enc_data)

        data = get_random_bytes(6000)
        enc_data = get_enc_data_pass(data, password)
        write_lv(aes_pass_dat, data)
        write_lv(aes_pass_dat, enc_data)

        data = get_random_bytes(8192)
        enc_data = get_enc_data_pass(data, password)
        write_lv(aes_pass_dat, data)
        write_lv(aes_pass_dat, enc_data)

        data = get_random_bytes(10000)
        enc_data = get_enc_data_pass(data, password)
        write_lv(aes_pass_dat, data)
        write_lv(aes_pass_dat, enc_data)

    with open('dummy.dat', 'wb') as dummy_dat:
        data = get_random_bytes(10000)
        dummy_dat.write(data)
    
    with open('dummy.dat', 'rb') as dummy_dat,\
         open('dummy.enckey.dat', 'wb') as dummy_key_dat:
        encrypt_key_stream(dummy_dat, dummy_key_dat, rsa_key, 'rsa_key1')
    
    with open('dummy.dat', 'rb') as dummy_dat,\
         open('dummy.encpass.dat', 'wb') as dummy_pass_dat:
        encrypt_pass_stream(dummy_dat, dummy_pass_dat, password)


if __name__ == '__main__':
    main()
