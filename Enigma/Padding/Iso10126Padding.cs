using Enigma.Random;
using System;

namespace Enigma.Padding
{
    /// <summary>
    /// Pad and unpad data with ISO 10126
    /// </summary>
    public sealed class Iso10126Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with ISO 10126
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

            if (paddingLength > 1)
            {
                byte[] rndBytes = RandomHelper.GenerateBytes(paddingLength - 1);
                Array.Copy(rndBytes, 0, paddedData, data.Length, paddingLength - 1);
            }

            paddedData[paddedData.Length - 1] = (byte)paddingLength;

            return paddedData;
        }

        /// <summary>
        /// Unpad data with ISO 10126
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

            int dataSize = paddedData.Length - paddedData[paddedData.Length - 1];

            byte[] unpaddedData = new byte[dataSize];
            Array.Copy(paddedData, 0, unpaddedData, 0, dataSize);

            return unpaddedData;
        }
    }
}
