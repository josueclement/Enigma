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

    /// <summary>
    /// Padding exception
    /// </summary>
    public sealed class PaddingException : Exception
    {
        /// <summary>
        /// Constructor for <see cref="PaddingException"/>
        /// </summary>
        /// <param name="message">Message</param>
        public PaddingException(string message) : base(message) { }
    }
}
