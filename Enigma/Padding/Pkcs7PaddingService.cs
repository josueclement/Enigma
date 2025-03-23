using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// Pkcs7 padding service
/// </summary>
public class Pkcs7PaddingService : PaddingServiceBase
{
    /// <inheritdoc />
    protected override IBlockCipherPadding BuildPadding()
        => new Org.BouncyCastle.Crypto.Paddings.Pkcs7Padding();
}