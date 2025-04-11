using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher parameters factory
/// </summary>
public class BlockCipherParametersFactory : IBlockCipherParametersFactory
{
    /// <inheritdoc />
    public ICipherParameters CreateEcbParameters(byte[] key)
        => new KeyParameter(key);

    /// <inheritdoc />
    public ICipherParameters CreateCbcParameters(byte[] key, byte[] iv)
        => new ParametersWithIV(new KeyParameter(key), iv);

    /// <inheritdoc />
    public ICipherParameters CreateSicParameters(byte[] key, byte[] nonce)
        => new ParametersWithIV(new KeyParameter(key), nonce);

    /// <inheritdoc />
    public ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, int macSize = 128)
        => new AeadParameters(new KeyParameter(key), macSize, nonce);

    /// <inheritdoc />
    public ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, byte[] associatedText, int macSize = 128)
        => new AeadParameters(new KeyParameter(key), macSize, nonce, associatedText);
}