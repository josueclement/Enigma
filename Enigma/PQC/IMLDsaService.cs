using Org.BouncyCastle.Crypto;

namespace Enigma.PQC;

/// <summary>
/// Provides cryptographic operations for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA),
/// a post-quantum cryptographic signature scheme that is resistant to quantum computing attacks.
/// </summary>
// ReSharper disable once InconsistentNaming
public interface IMLDsaService
{
    /// <summary>
    /// Generates a new asymmetric key pair for use with ML-DSA signatures.
    /// </summary>
    /// <returns>An asymmetric key pair containing both public and private keys.</returns>
    AsymmetricCipherKeyPair GenerateKeyPair();
    
    /// <summary>
    /// Signs the specified data using the provided private key.
    /// </summary>
    /// <param name="data">The data to be signed, represented as a byte array.</param>
    /// <param name="privateKey">The private key used for signing the data.</param>
    /// <returns>A byte array containing the cryptographic signature.</returns>
    byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey);
    
    /// <summary>
    /// Verifies that a signature is valid for the given data using the provided public key.
    /// </summary>
    /// <param name="data">The original data that was signed, represented as a byte array.</param>
    /// <param name="signature">The signature to verify, represented as a byte array.</param>
    /// <param name="publicKey">The public key corresponding to the private key used for signing.</param>
    /// <returns>True if the signature is valid for the given data and public key; otherwise, false.</returns>
    bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey);
}