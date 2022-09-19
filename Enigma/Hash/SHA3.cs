using Enigma.IO;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Hash
{
    /// <summary>
    /// Hash data with SHA3
    /// </summary>
    public static class SHA3
    {
        /// <summary>
        /// Hash data with SHA3
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <param name="bitLength">SHA3 bit length</param>
        /// <returns>SHA3 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(byte[] data, int bitLength = 512)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = new byte[bitLength / 8];

            Sha3Digest sha3 = new Sha3Digest(bitLength);
            sha3.BlockUpdate(data, 0, data.Length);
            sha3.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with SHA3
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bitLength">SHA3 bit length</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA3 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(Stream input, int bitLength = 512, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[bitLength / 8];

            Sha3Digest sha3 = new Sha3Digest(bitLength);
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha3.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha3.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Asynchronously hash data from stream with SHA3
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bitLength">SHA3 bit length</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA3 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task<byte[]> HashAsync(Stream input, int bitLength = 512, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[bitLength / 8];

            Sha3Digest sha3 = new Sha3Digest(bitLength);
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                    sha3.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha3.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA3
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bitLength">SHA3 bit length</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA3 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(string inputFile, int bitLength = 512, int bufferSize = 4096)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));

            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return Hash(fs, bitLength, bufferSize);
            }
        }

        /// <summary>
        /// Asynchronously hash file with SHA3
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bitLength">SHA3 bit length</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA3 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task<byte[]> HashAsync(string inputFile, int bitLength = 512, int bufferSize = 4096)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));

            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return await HashAsync(fs, bitLength, bufferSize).ConfigureAwait(false);
            }
        }
    }
}
