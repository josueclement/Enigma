using Org.BouncyCastle.Crypto;

namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service
/// </summary>
// ReSharper disable once InconsistentNaming
public interface IMLKemService
{
    /// <summary>
    /// Generate key pair
    /// </summary>
    /// <returns>Key pair</returns>
    AsymmetricCipherKeyPair GenerateKeyPair();

    /// <summary>
    /// Encapsulate a secret
    /// </summary>
    /// <param name="publicKey">Public key</param>
    /// <returns>(encapsulation, secret)</returns>
    (byte[] encapsulation, byte[] secret) Encapsulate(AsymmetricKeyParameter publicKey);

    /// <summary>
    /// Decapsulate a secret
    /// </summary>
    /// <param name="privateKey">Private key</param>
    /// <param name="encapsulation">Encapsulation</param>
    /// <returns>Secret</returns>
    byte[] Decapsulate(AsymmetricKeyParameter privateKey, byte[] encapsulation);
}