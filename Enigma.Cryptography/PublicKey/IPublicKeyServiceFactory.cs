namespace Enigma.Cryptography.PublicKey;
/// <summary>
/// Factory responsible for creating instances of public-key cryptographic services.
/// Provides methods to instantiate specific implementations of <see cref="IPublicKeyService"/>
/// based on different algorithms.
/// </summary>
public interface IPublicKeyServiceFactory
{
    /// <summary>
    /// Creates an RSA-based implementation of the public-key service.
    /// </summary>
    /// <param name="signerAlgorithm">
    /// The algorithm used for digital signatures. 
    /// Default is "SHA256withRSA" which uses SHA-256 for hashing combined with RSA for encryption.
    /// Other possible values might include "SHA1withRSA", "SHA384withRSA", or "SHA512withRSA".
    /// </param>
    /// <returns>
    /// An initialized instance of <see cref="IPublicKeyService"/> configured to use RSA algorithm
    /// for cryptographic operations.
    /// </returns>
    public IPublicKeyService CreateRsaService(string signerAlgorithm = "SHA256withRSA");
}
