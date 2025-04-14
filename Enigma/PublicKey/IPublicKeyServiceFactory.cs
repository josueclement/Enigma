namespace Enigma.PublicKey;

/// <summary>
/// Definition for public-key service factory
/// </summary>
public interface IPublicKeyServiceFactory
{
    /// <summary>
    /// Create a RSA public-key service
    /// </summary>
    /// <param name="signerAlgorithm">Signer algorithm</param>
    public IPublicKeyService CreateRsaService(string signerAlgorithm = "SHA256withRSA");
}