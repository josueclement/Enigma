using System;
using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// Padding base class
/// </summary>
public abstract class PaddingServiceBase : IPaddingService
{
    /// <summary>
    /// Abstract padding factory method
    /// </summary>
    /// <returns>Padding</returns>
    protected abstract IBlockCipherPadding BuildPadding();
    
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
    {
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

        var paddingLength = blockSize - data.Length % blockSize;
        var paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, 0, paddedData, 0, data.Length);

        var padding = BuildPadding();
        padding.AddPadding(paddedData, data.Length);

        return paddedData;
    }

    /// <inheritdoc />
    public byte[] UnPad(byte[] data, int blockSize)
    {
        if (blockSize is < 1 or > byte.MaxValue)
            throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));
        if (data.Length % blockSize != 0 || data.Length < blockSize)
            throw new ArgumentException($"Invalid padded data length {data.Length}");

        var padding = BuildPadding();
        var paddingLength = padding.PadCount(data);

        var unpaddedData = new byte[data.Length - paddingLength];
        Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

        return unpaddedData;
    }
}