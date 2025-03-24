using Org.BouncyCastle.Crypto;

namespace Enigma.PublicKey;

/// <summary>
/// Public-key service base class
/// </summary>
public abstract class PublicKeyServiceBase : IPublicKeyService
{
    /// <summary>
    /// Abstract key pair generator factory method
    /// </summary>
    /// <param name="keySize">Key size</param>
    /// <returns>Key pair generator</returns>
    protected abstract IAsymmetricCipherKeyPairGenerator BuildKeyPairGenerator(int keySize);
    
    /// <summary>
    /// Abstract cipher factory method
    /// </summary>
    /// <param name="forEncryption">True for encryption, False for decryption</param>
    /// <param name="key">Key</param>
    /// <returns>Cipher</returns>
    protected abstract IAsymmetricBlockCipher BuildCipher(bool forEncryption, AsymmetricKeyParameter key);
    
    /// <summary>
    /// Abstract signer factory method
    /// </summary>
    /// <param name="forSigning">True for signing, False for verifying</param>
    /// <param name="key">Key</param>
    /// <returns>Signer</returns>
    protected abstract ISigner BuildSigner(bool forSigning, AsymmetricKeyParameter key);
    
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair(int keySize)
    {
        var generator = BuildKeyPairGenerator(keySize);
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
    {
        var cipher = BuildCipher(forEncryption: true, key: publicKey);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var cipher = BuildCipher(forEncryption: false, key: privateKey);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = BuildSigner(forSigning: true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature(); 
    }

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
    {
        var signer = BuildSigner(forSigning: false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}