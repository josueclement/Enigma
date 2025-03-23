namespace Enigma.DataEncoding;

public class Hex : IEncodingService
{
    public string Encode(byte[] data)
        => Org.BouncyCastle.Utilities.Encoders.Hex.ToHexString(data);

    public byte[] Decode(string data)
        => Org.BouncyCastle.Utilities.Encoders.Hex.Decode(data);
}