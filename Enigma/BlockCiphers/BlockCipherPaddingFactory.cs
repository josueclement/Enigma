using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.BlockCiphers;

/// <summary>
/// Factory for creating various block cipher padding implementations.
/// Provides methods to instantiate standard padding mechanisms such as PKCS7, ISO7816, ISO10126, and X923.
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