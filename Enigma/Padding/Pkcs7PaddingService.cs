using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// A padder that adds PKCS7/PKCS5 padding to a block.
/// </summary>
public class Pkcs7PaddingService : PaddingServiceBase
{
    /// <inheritdoc />
    protected override IBlockCipherPadding BuildPadder()
        => new Pkcs7Padding();
}