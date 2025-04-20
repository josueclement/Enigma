using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.DataEncoding;

/// <summary>
/// Provides methods for encoding and decoding data using the Base64 algorithm.
/// </summary>
public class Base64Service : IEncodingService
{
    /// <inheritdoc />
    public string Encode(byte[] data)
        => Base64.ToBase64String(data);

    /// <inheritdoc />
    public byte[] Decode(string data)
        => Base64.Decode(data);
}