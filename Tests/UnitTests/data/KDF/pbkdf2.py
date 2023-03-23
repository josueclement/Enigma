import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1


def main():

    d = { 'password': [], 'salt': [], 'key': [] }

    for i in range(10):
        password = get_random_bytes(8).hex()
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, 32, count=50000, hmac_hash_module=SHA1)

        d['password'].append(password)
        d['salt'].append(salt.hex())
        d['key'].append(key.hex())

    pd.DataFrame(d).to_csv('pbkdf2.csv', index=False)


if __name__ == '__main__':
    main()
