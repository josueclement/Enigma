import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES


def main():

    d = { 'key': [], 'iv': [], 'data': [], 'enc': [] }

    # Generate random data
    for i in range(1, 21):
        key = get_random_bytes(32)
        iv = get_random_bytes(16)
        data = get_random_bytes(i * 16)
        
        # Encrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        enc = cipher.encrypt(data)

        d['key'].append(key.hex())
        d['iv'].append(iv.hex())
        d['data'].append(data.hex())
        d['enc'].append(enc.hex())
    
    # Save to csv
    pd.DataFrame(d).to_csv('aes.csv', index=False)


if __name__ == '__main__':
    main()
