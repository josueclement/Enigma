using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// A padder that adds ISO10126-2 padding to a block.
/// </summary>
public class Iso10126PaddingService : PaddingServiceBase
{
    /// <inheritdoc />
    protected override IBlockCipherPadding BuildPadder()
        => new ISO10126d2Padding();
}