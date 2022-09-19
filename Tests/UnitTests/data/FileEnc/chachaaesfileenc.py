from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
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
    chacha_key = get_random_bytes(32)
    chacha_nonce = get_random_bytes(12)
    aes_key = get_random_bytes(32)
    aes_iv = get_random_bytes(16)

    with BytesIO() as ms:
        write_lv(ms, chacha_key)
        write_lv(ms, chacha_nonce)
        write_lv(ms, aes_key)
        write_lv(ms, aes_iv)
        ms.seek(0)
        key_data = ms.read()
    
    enc_key_data = encrypt(rsa, key_data)

    output_stream.write(b'CAENCR!')
    output_stream.write(b'\x05')
    write_lv(output_stream, key_name.encode('ascii'))
    write_lv(output_stream, enc_key_data)
    
    encrypt_and_pad(input_stream, output_stream, chacha_key, chacha_nonce, aes_key, aes_iv)


def encrypt_pass_stream(input_stream: BinaryIO,
                        output_stream: BinaryIO,
                        password: str) -> None:
    chacha_salt = get_random_bytes(16)
    chacha_key = PBKDF2(password, chacha_salt, 32, count=60000, hmac_hash_module=SHA1)
    chacha_nonce = get_random_bytes(12)

    aes_salt = get_random_bytes(16)
    aes_key = PBKDF2(password, aes_salt, 32, count=60000, hmac_hash_module=SHA1)
    aes_iv = get_random_bytes(16)

    output_stream.write(b'CAENCP!')
    output_stream.write(b'\x05')
    write_lv(output_stream, chacha_salt)
    write_lv(output_stream, chacha_nonce)
    write_lv(output_stream, aes_salt)
    write_lv(output_stream, aes_iv)
    
    encrypt_and_pad(input_stream, output_stream, chacha_key, chacha_nonce, aes_key, aes_iv)


def encrypt_and_pad(input_stream: BinaryIO,
                    output_stream: BinaryIO,
                    chacha_key: bytes,
                    chacha_nonce: bytes,
                    aes_key: bytes,
                    aes_iv: bytes):
    pad_done = False
    buffer = None

    while True:
        buffer = input_stream.read(4096)

        if len(buffer) == 4096:
            gen_pad_xor_encrypt_write(output_stream, len(buffer), buffer, chacha_key, chacha_nonce, aes_key, aes_iv)
        elif len(buffer) > 0:
            pad_data = pad(buffer, 16, 'pkcs7')
            pad_done = True
            gen_pad_xor_encrypt_write(output_stream, len(pad_data), pad_data, chacha_key, chacha_nonce, aes_key, aes_iv)
        
        if len(buffer) != 4096:
            break
    
    if not pad_done:
        pad_data = pad(b'', 16, 'pkcs7')
        gen_pad_xor_encrypt_write(output_stream, len(pad_data), pad_data, chacha_key, chacha_nonce, aes_key, aes_iv)

    write_lv(output_stream, b'')


def gen_pad_xor_encrypt_write(output_stream: BytesIO,
                              pad_size: int,
                              data: bytes,
                              chacha_key: bytes,
                              chacha_nonce: bytes,
                              aes_key: bytes,
                              aes_iv: bytes):
    rpad = get_random_bytes(pad_size)
    xor = bytearray(pad_size)

    for i in range(pad_size):
        xor[i] = data[i] ^ rpad[i]
    
    chacha_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    d1 = chacha_cipher.encrypt(rpad)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    d2 = aes_cipher.encrypt(xor)

    write_lv(output_stream, d1)
    write_lv(output_stream, d2)


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
        encrypt_key_stream(input_stream, output_stream, rsa_key, 'rsa_key2')
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

    with open('pub_key2.pem', 'wb') as pub_pem1:
        save_public_key_to_pem(rsa_key, pub_pem1)

    with open('pk_key2.pem', 'wb') as pk_pem1:
        save_private_key_to_pem(rsa_key, pk_pem1, 'test1234')

    with open('chachaaesfileenc_key.dat', 'wb') as aes_key_dat:
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

    with open('chachaaesfileenc_pass.dat', 'wb') as aes_pass_dat:
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

    with open('dummy2.dat', 'wb') as dummy_dat:
        data = get_random_bytes(10000)
        dummy_dat.write(data)
    
    with open('dummy2.dat', 'rb') as dummy_dat,\
         open('dummy2.enckey.dat', 'wb') as dummy_key_dat:
        encrypt_key_stream(dummy_dat, dummy_key_dat, rsa_key, 'rsa_key2')
    
    with open('dummy2.dat', 'rb') as dummy_dat,\
         open('dummy2.encpass.dat', 'wb') as dummy_pass_dat:
        encrypt_pass_stream(dummy_dat, dummy_pass_dat, password)


if __name__ == '__main__':
    main()
