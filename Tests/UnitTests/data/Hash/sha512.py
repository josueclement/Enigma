import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512


def main():
    
    d = { 'data': [], 'hash': [] }

    # Generate random data
    for i in range(20):
        data = get_random_bytes(i)
        d['data'].append(data.hex())
        d['hash'].append(SHA512.new(data).hexdigest())

    # Save to csv
    pd.DataFrame(d).to_csv('sha512.csv', index=False)

    # Hash file
    with open('sha512.csv', 'rb') as sha512_csv:
        data = sha512_csv.read()
        sha512 = SHA512.new(data)
    
    # Write hash
    with open('sha512.csv.txt', 'w') as sha512_csv_txt:
        sha512_csv_txt.write(sha512.hexdigest())
    

if __name__ == '__main__':
    main()
