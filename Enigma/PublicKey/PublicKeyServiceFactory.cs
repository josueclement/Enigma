using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Enigma.PublicKey;

/// <summary>
/// Public-key service factory
/// </summary>
public class PublicKeyServiceFactory : IPublicKeyServiceFactory
{
    /// <summary>
    /// Create a RSA public-key service
    /// </summary>
    /// <param name="signerAlgorithm"></param>
    /// <returns></returns>
    public IPublicKeyService CreateRsaService(string signerAlgorithm = "SHA256withRSA")
        => new PublicKeyService(
            cipherFactory: () => new Pkcs1Encoding(new RsaEngine()),
            keyPairGeneratorFactory: () => new RsaKeyPairGenerator(),
            signerFactory: () => SignerUtilities.GetSigner(signerAlgorithm));
}