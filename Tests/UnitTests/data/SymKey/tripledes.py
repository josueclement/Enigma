import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES3


def main():

    d = { 'key': [], 'iv': [], 'data': [], 'enc': [] }

    # Generate random data
    for i in range(1, 21):
        key = get_random_bytes(24)
        iv = get_random_bytes(8)
        data = get_random_bytes(i * 16)
        
        # Encrypt data
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        enc = cipher.encrypt(data)

        d['key'].append(key.hex())
        d['iv'].append(iv.hex())
        d['data'].append(data.hex())
        d['enc'].append(enc.hex())
    
    # Save to csv
    pd.DataFrame(d).to_csv('tripledes.csv', index=False)


if __name__ == '__main__':
    main()
