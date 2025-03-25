using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.StreamCiphers;

/// <summary>
/// ChaCha20 encryption/decryption service
/// </summary>
public class ChaCha20Service : StreamCipherServiceBase
{
    /// <inheritdoc />
    public override int KeySize => 32;
    
    /// <inheritdoc />
    public override int NonceSize => 8;
    
    /// <inheritdoc />
    protected override IStreamCipher BuildCipher(bool forEncryption, byte[] key, byte[] nonce)
    {
        var cipher = new ChaChaEngine();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(forEncryption, parameters);
        return cipher;
    }
}