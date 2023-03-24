import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256


def main():
    
    d = { 'data': [], 'hash': [] }

    # Generate random data
    for i in range(20):
        data = get_random_bytes(i)
        d['data'].append(data.hex())
        d['hash'].append(SHA256.new(data).hexdigest())

    # Save to csv
    pd.DataFrame(d).to_csv('sha256.csv', index=False)

    # Hash file
    with open('sha256.csv', 'rb') as sha256_csv:
        data = sha256_csv.read()
        sha256 = SHA256.new(data)
    
    # Write hash
    with open('sha256.csv.txt', 'w') as sha256_csv_txt:
        sha256_csv_txt.write(sha256.hexdigest())
    

if __name__ == '__main__':
    main()
