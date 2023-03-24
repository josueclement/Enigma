import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5


def main():
    
    d = { 'data': [], 'hash': [] }

    # Generate random data
    for i in range(20):
        data = get_random_bytes(i)
        d['data'].append(data.hex())
        d['hash'].append(MD5.new(data).hexdigest())

    # Save to csv
    pd.DataFrame(d).to_csv('md5.csv', index=False)

    # Hash file
    with open('md5.csv', 'rb') as md5_csv:
        data = md5_csv.read()
        md5 = MD5.new(data)
    
    # Write hash
    with open('md5.csv.txt', 'w') as md5_csv_txt:
        md5_csv_txt.write(md5.hexdigest())
    

if __name__ == '__main__':
    main()
