using Org.BouncyCastle.Crypto.Paddings;
using System;

namespace Enigma.Padding;

/// <summary>
/// Provides padding and unpadding functionality for block cipher operations.
/// This service uses BouncyCastle's padding mechanisms to ensure data blocks
/// are properly sized for encryption and decryption operations.
/// </summary>
/// <remarks>
/// The service is initialized with a factory function that creates padding instances.
/// It supports padding data to match block size requirements and removing padding
/// from previously padded data.
/// </remarks>
/// <param name="paddingFactory">Factory function that creates IBlockCipherPadding instances</param>
public class PaddingService(Func<IBlockCipherPadding> paddingFactory) : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
    {
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

        var paddingLength = blockSize - data.Length % blockSize;
        var paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);

        var padder = paddingFactory();
        padder.AddPadding(paddedData, data.Length);

        return paddedData;
    }

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize)
    {
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));
        if (data.Length % blockSize != 0 || data.Length < blockSize)
            throw new ArgumentException($"Invalid padded data length {data.Length}");

        var padder = paddingFactory();
        var paddingLength = padder.PadCount(data);

        var unpaddedData = new byte[data.Length - paddingLength];
        Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

        return unpaddedData;
    }
}