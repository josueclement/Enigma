using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.DataEncoding;

/// <summary>
/// Hexadecimal encoding service
/// </summary>
public class HexService : IEncodingService
{
    /// <inheritdoc />
    public string Encode(byte[] data)
        => Hex.ToHexString(data);

    /// <inheritdoc />
    public byte[] Decode(string data)
        => Hex.Decode(data);
}