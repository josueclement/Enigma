import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_512


def main():

    d = { 'data': [], 'hash': [] }

    # Generate random data
    for i in range(20):
        data = get_random_bytes(i)
        d['data'].append(data.hex())
        d['hash'].append(SHA3_512.new(data).hexdigest())

    # Save to csv
    pd.DataFrame(d).to_csv('sha3.csv', index=False)

    # Hash file
    with open('sha3.csv', 'rb') as sha3_csv:
        data = sha3_csv.read()
        sha3 = SHA3_512.new(data)
    
    # Write hash
    with open('sha3.csv.txt', 'w') as sha3_csv_txt:
        sha3_csv_txt.write(sha3.hexdigest())

    

if __name__ == '__main__':
    main()
