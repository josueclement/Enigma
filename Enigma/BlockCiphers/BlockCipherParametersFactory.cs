using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Factory for creating various block cipher parameters used in cryptographic operations.
/// This class implements the <see cref="IBlockCipherParametersFactory"/> interface and 
/// provides methods to create parameters for different cipher modes including ECB, CBC, 
/// SIC (CTR mode), and GCM, with appropriate initialization vectors and authentication data.
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