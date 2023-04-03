import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1


def main():
    
    d = { 'data': [], 'hash': [] }

    # Generate random data
    for i in range(20):
        data = get_random_bytes(i)
        d['data'].append(data.hex())
        d['hash'].append(SHA1.new(data).hexdigest())

    # Save to csv
    pd.DataFrame(d).to_csv('sha1.csv', index=False)

    # Hash file
    with open('sha1.csv', 'rb') as sha1_csv:
        data = sha1_csv.read()
        sha1 = SHA1.new(data)
    
    # Write hash
    with open('sha1.csv.txt', 'w') as sha1_csv_txt:
        sha1_csv_txt.write(sha1.hexdigest())
    

if __name__ == '__main__':
    main()
