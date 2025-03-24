using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// A padder that adds X9.23 padding to a block - if a SecureRandom is passed in random padding is assumed,
/// otherwise padding with zeros is used.
/// </summary>
public class X923PaddingService : PaddingServiceBase
{
    /// <inheritdoc />
    protected override IBlockCipherPadding BuildPadder()
        => new X923Padding();
}