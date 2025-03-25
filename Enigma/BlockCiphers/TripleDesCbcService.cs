using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// 3DES-CBC encryption/decryption service
/// </summary>
public class TripleDesCbcService : BlockCipherServiceBase
{
    /// <inheritdoc />
    public override int KeySize => 24;
    
    /// <inheritdoc />
    public override int IvSize => 8;
    
    /// <inheritdoc />
    public override int BlockSize => 8;

    /// <inheritdoc />
    protected override IBufferedCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.Init(forEncryption, parameters);
        return cipher;
    }
}