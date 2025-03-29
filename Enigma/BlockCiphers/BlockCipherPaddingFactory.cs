using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher padding factory
/// </summary>
public class BlockCipherPaddingFactory : IBlockCipherPaddingFactory
{
    /// <inheritdoc />
    public IBlockCipherPadding CreatePkcs7Padding() => new Pkcs7Padding();

    /// <inheritdoc />
    public IBlockCipherPadding CreateIso7816Padding() => new ISO7816d4Padding();

    /// <inheritdoc />
    public IBlockCipherPadding CreateIso10126Padding() => new ISO10126d2Padding();

    /// <inheritdoc />
    public IBlockCipherPadding CreateX923Padding() => new X923Padding();
}