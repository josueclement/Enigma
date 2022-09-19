using System;

namespace Enigma.Padding
{
    /// <summary>
    /// No padding class using IDataPadding
    /// </summary>
    public sealed class NoPadding : IDataPadding
    {
        /// <summary>
        /// Only returns the input data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Original data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Pad(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

            return data;
        }

        /// <summary>
        /// Only returns the input data
        /// </summary>
        /// <param name="paddedData">Data</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Original data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Unpad(byte[] paddedData, int blockSize)
        {
            if (paddedData == null)
                throw new ArgumentNullException(nameof(paddedData));
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

            return paddedData;
        }
    }
}
