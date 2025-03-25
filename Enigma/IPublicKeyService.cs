using Org.BouncyCastle.Crypto;

namespace Enigma;

/// <summary>
/// Definition for public-key services
/// </summary>
public interface IPublicKeyService
{
    /// <summary>
    /// Generate key pair
    /// </summary>
    /// <param name="keySize">Key size</param>
    /// <returns>Key pair</returns>
    AsymmetricCipherKeyPair GenerateKeyPair(int keySize);
    
    /// <summary>
    /// Encrypt data with public key
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <param name="publicKey">Public key</param>
    /// <returns>Encrypted data</returns>
    byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey);
    
    /// <summary>
    /// Decrypt data with private key
    /// </summary>
    /// <param name="data">Data to decrypt</param>
    /// <param name="privateKey">Private key</param>
    /// <returns>Decrypted data</returns>
    byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey);
    
    /// <summary>
    /// Sign data with private key
    /// </summary>
    /// <param name="data">Data to sign</param>
    /// <param name="privateKey">Private key</param>
    /// <returns>Signature</returns>
    byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey);
    
    /// <summary>
    /// Verify signature
    /// </summary>
    /// <param name="data">Data to verify</param>
    /// <param name="signature">Signature</param>
    /// <param name="publicKey">Public key</param>
    /// <returns>True if signature is valid, otherwise false</returns>
    bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey);
}