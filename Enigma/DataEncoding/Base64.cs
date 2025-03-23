namespace Enigma.DataEncoding;

public class Base64 : IEncodingService
{
    public string Encode(byte[] data)
        => Org.BouncyCastle.Utilities.Encoders.Base64.ToBase64String(data);

    public byte[] Decode(string data)
        => Org.BouncyCastle.Utilities.Encoders.Base64.Decode(data);
}