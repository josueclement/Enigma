namespace Enigma.Padding;

/// <summary>
/// No padding service
/// </summary>
public class NoPaddingService : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
        => data;

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize)
        => data;
}