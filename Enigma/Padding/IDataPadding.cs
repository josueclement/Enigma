using System;

namespace Enigma.Padding
{
    /// <summary>
    /// Interface defining Pad and Unpad methods
    /// </summary>
    public interface IDataPadding
    {
        /// <summary>
        /// Pad data
        /// </summary>
        /// <param name="data">Data to pad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Padded data</returns>
        byte[] Pad(byte[] data, int blockSize);

        /// <summary>
        /// Unpad data
        /// </summary>
        /// <param name="paddedData">Data to unpad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Unpadded data</returns>
        byte[] Unpad(byte[] paddedData, int blockSize);
    }

    public sealed class PaddingException : Exception
    {
        public PaddingException(string message) : base(message) { }
    }
}
