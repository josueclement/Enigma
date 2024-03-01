using System;

namespace Enigma.Padding
{
    /// <summary>
    /// No padding class using IDataPadding
    /// </summary>
    public sealed class NoPadding : IDataPadding
    {
        static NoPadding()
        {
            Instance = new NoPadding();
        }
        
        /// <summary>
        /// Static instance
        /// </summary>
        public static NoPadding Instance { get; }
        
        /// <summary>
        /// Only returns the input data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Original data</returns>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Pad(byte[] data, int blockSize)
        {
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
        /// <exception cref="ArgumentException"></exception>
        public byte[] Unpad(byte[] paddedData, int blockSize)
        {
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

            return paddedData;
        }
    }
}
