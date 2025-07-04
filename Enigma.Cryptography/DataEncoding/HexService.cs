using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.Cryptography.DataEncoding;

/// <summary>
/// Provides methods for encoding and decoding data using hexadecimal representation.
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