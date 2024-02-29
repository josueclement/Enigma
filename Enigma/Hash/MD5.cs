using Enigma.IO;
using Org.BouncyCastle.Crypto.Digests;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Hash
{
    /// <summary>
    /// Hash data with MD5
    /// </summary>
    public static class MD5
    {
        /// <summary>
        /// MD5 hash size
        /// </summary>
        public const int HASH_SIZE = 16;

        /// <summary>
        /// Hash data with MD5
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>MD5 hash</returns>
        public static byte[] Hash(byte[] data)
        {
            byte[] result = new byte[HASH_SIZE];

            MD5Digest md5 = new MD5Digest();
            md5.BlockUpdate(data, 0, data.Length);
            md5.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with MD5
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[HASH_SIZE];

            MD5Digest md5 = new MD5Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    md5.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            md5.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Asynchronously hash data from stream with MD5
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        public static async Task<byte[]> HashAsync(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[HASH_SIZE];

            MD5Digest md5 = new MD5Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                    md5.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            md5.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with MD5
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        public static byte[] Hash(string inputFile, int bufferSize = 4096)
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return Hash(fs, bufferSize);
            }
        }

        /// <summary>
        /// Asynchronously hash file with MD5
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        public static async Task<byte[]> HashAsync(string inputFile, int bufferSize = 4096)
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return await HashAsync(fs, bufferSize).ConfigureAwait(false);
            }
        }
    }
}
