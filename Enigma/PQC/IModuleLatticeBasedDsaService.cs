using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace Enigma.PQC;

/// <summary>
/// Definition for Module-Lattice-Based digital signature algorithm (ML-DSA) services
/// </summary>
public interface IModuleLatticeBasedDsaService
{
    /// <summary>
    /// Generate key pair
    /// </summary>
    /// <returns>Key pair</returns>
    AsymmetricCipherKeyPair GenerateKeyPair();
    
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