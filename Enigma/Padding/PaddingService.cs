using Org.BouncyCastle.Crypto.Paddings;
using System;

namespace Enigma.Padding;

/// <summary>
/// Padding service
/// </summary>
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