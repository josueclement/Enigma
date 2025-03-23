using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// AES-CBC encryption/decryption service
/// </summary>
public class AesCbc : BlockCipherServiceBase
{
    /// <inheritdoc />
    public override int KeySize => 32;
    
    /// <inheritdoc />
    public override int IvSize => 16;
    
    /// <inheritdoc />
    public override int BlockSize => 16;

    /// <inheritdoc />
    protected override IBufferedCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv, IBlockCipherPadding padding)
    {
        var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), padding);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.Init(forEncryption, parameters);
        return cipher;
    }
}