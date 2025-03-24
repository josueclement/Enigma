using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Enigma.PublicKey;

/// <summary>
/// RSA service
/// </summary>
public class RsaService : PublicKeyServiceBase
{
    /// <inheritdoc />
    protected override IAsymmetricCipherKeyPairGenerator BuildKeyPairGenerator(int keySize)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator;
    }

    /// <inheritdoc />
    protected override IAsymmetricBlockCipher BuildCipher(bool forEncryption, AsymmetricKeyParameter key)
    {
        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption, key);
        return cipher;
    }

    /// <inheritdoc />
    protected override ISigner BuildSigner(bool forSigning, AsymmetricKeyParameter key)
    {
        var signer = SignerUtilities.GetSigner("SHA256withRSA");
        signer.Init(forSigning, key);
        return signer;
    }
}