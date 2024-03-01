using Enigma.IO;
using Org.BouncyCastle.Crypto.Digests;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Hash
{
    /// <summary>
    /// Hash data with SHA256
    /// </summary>
    public static class SHA256
    {
        /// <summary>
        /// SHA256 hash size
        /// </summary>
        public const int HASH_SIZE = 32;

        /// <summary>
        /// Hash data with SHA256
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>SHA256 hash</returns>
        public static byte[] Hash(byte[] data)
        {
            byte[] result = new byte[HASH_SIZE];

            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(data, 0, data.Length);
            sha256.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with SHA256
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA256 hash</returns>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[HASH_SIZE];

            Sha256Digest sha256 = new Sha256Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha256.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha256.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Asynchronously hash data from stream with SHA256
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA256 hash</returns>
        public static async Task<byte[]> HashAsync(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[HASH_SIZE];

            Sha256Digest sha256 = new Sha256Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                    sha256.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha256.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA256
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA256 hash</returns>
        public static byte[] Hash(string inputFile, int bufferSize = 4096)
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return Hash(fs, bufferSize);
            }
        }

        /// <summary>
        /// Asynchronously hash file with SHA256
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA256 hash</returns>
        public static async Task<byte[]> HashAsync(string inputFile, int bufferSize = 4096)
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return await HashAsync(fs, bufferSize).ConfigureAwait(false);
            }
        }
    }
}
