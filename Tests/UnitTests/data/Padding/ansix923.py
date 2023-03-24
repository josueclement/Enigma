import pandas as pd
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def main():

    d = { 'data': [], 'padded': [] }

    # Generate random data
    for i in range(50):
        data = get_random_bytes(i)
        padded = pad(data, 16, 'x923')
        d['data'].append(data.hex())
        d['padded'].append(padded.hex())

    # Save to csv
    pd.DataFrame(d).to_csv('ansix923.csv', index=False)


if __name__ == '__main__':
    main()
