using Org.BouncyCastle.Crypto;

namespace Enigma.PublicKey;
/// <summary>
/// Provides cryptographic operations using asymmetric (public-key) encryption.
/// This service handles key generation, encryption/decryption, and digital signature operations.
/// </summary>
/// <remarks>
/// Implementations should follow best practices for cryptographic operations and
/// ensure proper key management (generation, storage, and disposal).
/// </remarks>
public interface IPublicKeyService
{
    /// <summary>
    /// Generates a new asymmetric key pair for encryption and signing operations.
    /// </summary>
    /// <param name="keySize">
    /// The size of the key in bits. Larger keys provide stronger security but may impact performance.
    /// Recommended minimum sizes depend on the algorithm (e.g., 2048 bits for RSA, 256 bits for ECC).
    /// </param>
    /// <returns>A new asymmetric key pair containing both public and private keys.</returns>
    /// <remarks>
    /// The generated key pair should be stored securely, with the private key protected
    /// from unauthorized access.
    /// </remarks>
    AsymmetricCipherKeyPair GenerateKeyPair(int keySize);
    
    /// <summary>
    /// Encrypts data using the recipient's public key, ensuring that only the holder
    /// of the corresponding private key can decrypt it.
    /// </summary>
    /// <param name="data">The raw data to encrypt. Should not be null or empty.</param>
    /// <param name="publicKey">The recipient's public key used for encryption.</param>
    /// <returns>The encrypted data as a byte array.</returns>
    /// <remarks>
    /// This method is typically used for securing data that will be transmitted to another party.
    /// For large data sets, consider using hybrid encryption (symmetric + asymmetric).
    /// </remarks>
    byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey);
    
    /// <summary>
    /// Decrypts data that was previously encrypted with the corresponding public key.
    /// </summary>
    /// <param name="data">The encrypted data to decrypt. Should not be null or empty.</param>
    /// <param name="privateKey">The private key matching the public key used for encryption.</param>
    /// <returns>The original, decrypted data as a byte array.</returns>
    /// <remarks>
    /// This operation should only be performed in secure contexts where the private key
    /// is protected from unauthorized access.
    /// </remarks>
    byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey);
    
    /// <summary>
    /// Creates a digital signature for the given data using the sender's private key.
    /// </summary>
    /// <param name="data">The data to sign. Should not be null or empty.</param>
    /// <param name="privateKey">The signer's private key used to create the signature.</param>
    /// <returns>A digital signature as a byte array that can be verified using the corresponding public key.</returns>
    /// <remarks>
    /// Digital signatures provide authentication (proof of sender identity) and integrity (proof that data
    /// hasn't been altered) but do not encrypt the data itself.
    /// </remarks>
    byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey);
    
    /// <summary>
    /// Verifies the authenticity of a digital signature using the signer's public key.
    /// </summary>
    /// <param name="data">The original data that was signed. Should not be null or empty.</param>
    /// <param name="signature">The signature to verify against the data.</param>
    /// <param name="publicKey">The signer's public key corresponding to the private key used for signing.</param>
    /// <returns>
    /// <c>true</c> if the signature is valid and matches the data; <c>false</c> if the signature is invalid
    /// or does not match the data.
    /// </returns>
    /// <remarks>
    /// A valid signature confirms both the identity of the signer (authentication) and
    /// that the data has not been modified since signing (integrity).
    /// </remarks>
    bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey);
}
