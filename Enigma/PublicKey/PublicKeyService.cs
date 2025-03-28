using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;

namespace Enigma.PublicKey;

/// <summary>
/// Public-key service
/// </summary>
/// <param name="cipherFactory">Cipher factory</param>
/// <param name="keyPairGeneratorFactory">Key pair generator factory</param>
/// <param name="signerFactory">Signer factory</param>
public class PublicKeyService(
    Func<IAsymmetricBlockCipher> cipherFactory,
    Func<IAsymmetricCipherKeyPairGenerator> keyPairGeneratorFactory,
    Func<ISigner> signerFactory) : IPublicKeyService
{
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair(int keySize)
    {
        var generator = keyPairGeneratorFactory();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
    {
        var cipher = cipherFactory();
        cipher.Init(forEncryption: true, publicKey);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var cipher = cipherFactory();
        cipher.Init(forEncryption: false, privateKey);
        return cipher.ProcessBlock(data, 0, data.Length); 
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = signerFactory();
        signer.Init(forSigning: true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
    {
        var signer = signerFactory();
        signer.Init(forSigning: false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}