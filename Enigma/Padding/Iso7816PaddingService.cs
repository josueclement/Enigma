using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// A padder that adds the padding according to the scheme referenced in ISO 7814-4 - scheme 2 from ISO 9797-1.
/// The first byte is 0x80, rest is 0x00
/// </summary>
public class Iso7816PaddingService : PaddingServiceBase
{
    /// <inheritdoc />
    protected override IBlockCipherPadding BuildPadder()
        => new ISO7816d4Padding();
}