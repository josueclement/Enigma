namespace Enigma;

/// <summary>
/// Definition for public-key service factory
/// </summary>
public interface IPublicKeyServiceFactory
{
    /// <summary>
    /// Create a RSA public-key service
    /// </summary>
    /// <param name="signerAlgorithm">Signer algorithm</param>
    public IPublicKeyService CreateRsaPublicKeyService(string signerAlgorithm);
}