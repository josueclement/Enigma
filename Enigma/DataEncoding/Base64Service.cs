using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.DataEncoding;

/// <summary>
/// Base64 encoding service
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