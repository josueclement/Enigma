using Org.BouncyCastle.Crypto;

namespace Enigma.Cryptography.PQC;

/// <summary>
/// Defines the Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM) service.
/// ML-KEM is a post-quantum cryptographic algorithm standardized by NIST that provides
/// quantum-resistant key encapsulation functionality based on the module learning with errors problem.
/// </summary>
// ReSharper disable once InconsistentNaming
public interface IMLKemService
{
    /// <summary>
    /// Generates a new ML-KEM key pair for use in key encapsulation operations.
    /// </summary>
    /// <returns>
    /// An <see cref="AsymmetricCipherKeyPair"/> containing both public and private keys
    /// that can be used for encapsulation and decapsulation operations.
    /// </returns>
    AsymmetricCipherKeyPair GenerateKeyPair();

    /// <summary>
    /// Encapsulates a randomly generated secret using the recipient's public key.
    /// This operation produces both the encapsulation (ciphertext) and the shared secret.
    /// </summary>
    /// <param name="publicKey">The recipient's ML-KEM public key used to encapsulate the secret.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>encapsulation: The encapsulated data (ciphertext) that should be transmitted to the recipient.</item>
    /// <item>secret: The shared secret that can be used for symmetric encryption or other cryptographic purposes.</item>
    /// </list>
    /// </returns>
    (byte[] encapsulation, byte[] secret) Encapsulate(AsymmetricKeyParameter publicKey);

    /// <summary>
    /// Decapsulates a previously encapsulated secret using the recipient's private key.
    /// This operation recovers the shared secret from the encapsulation.
    /// </summary>
    /// <param name="encapsulation">The encapsulated data (ciphertext) received from the sender.</param>
    /// <param name="privateKey">The recipient's ML-KEM private key used to recover the secret.</param>
    /// <returns>
    /// The recovered shared secret that can be used for symmetric encryption or other cryptographic purposes.
    /// This should match the secret generated during the encapsulation operation.
    /// </returns>
    byte[] Decapsulate(byte[] encapsulation, AsymmetricKeyParameter privateKey);
}