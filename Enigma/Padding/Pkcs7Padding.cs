using System;

namespace Enigma.Padding
{
    /// <summary>
    /// Pad and unpad data with PKCS#7
    /// </summary>
    public sealed class Pkcs7Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with PKCS#7
        /// </summary>
        /// <param name="data">Data to pad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Padded data</returns>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Pad(byte[] data, int blockSize)
        {
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

            int paddingLength = blockSize - data.Length % blockSize;
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            for (int i = data.Length; i < paddedData.Length; i++)
                paddedData[i] = (byte)paddingLength;

            return paddedData;
        }

        /// <summary>
        /// Unpad data with PKCS#7
        /// </summary>
        /// <param name="paddedData">Data to unpad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Unpadded data</returns>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="PaddingException"></exception>
        public byte[] Unpad(byte[] paddedData, int blockSize)
        {
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));
            if (paddedData.Length % blockSize != 0 || paddedData.Length < blockSize)
                throw new PaddingException($"Invalid padded data length {paddedData.Length}");

            byte paddingLength = paddedData[paddedData.Length - 1];

            for (int i = paddedData.Length - 2; i >= paddedData.Length - paddingLength; i--)
            {
                if (paddedData[i] != paddingLength)
                    throw new PaddingException("Invalid Pkcs7 padding");
            }

            byte[] unpaddedData = new byte[paddedData.Length - paddingLength];
            Array.Copy(paddedData, 0, unpaddedData, 0, paddedData.Length - paddingLength);

            return unpaddedData;
        }
    }
}
