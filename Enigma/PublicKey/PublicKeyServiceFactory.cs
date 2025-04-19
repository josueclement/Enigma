using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Enigma.PublicKey;

/// <summary>
/// Factory class for creating public key cryptography service instances.
/// Provides methods to create specific implementations of <see cref="IPublicKeyService"/>,
/// configured with appropriate cryptographic engines and algorithms.
/// </summary>
/// <remarks>
/// This factory simplifies the creation of cryptographic service instances by encapsulating
/// the configuration of underlying cryptographic components from the BouncyCastle library.
/// Currently supports RSA encryption with configurable signing algorithms.
/// </remarks>
public class PublicKeyServiceFactory : IPublicKeyServiceFactory
{
    /// <inheritdoc />
    public IPublicKeyService CreateRsaService(string signerAlgorithm = "SHA256withRSA")
        => new PublicKeyService(
            cipherFactory: () => new Pkcs1Encoding(new RsaEngine()),
            keyPairGeneratorFactory: () => new RsaKeyPairGenerator(),
            signerFactory: () => SignerUtilities.GetSigner(signerAlgorithm));
}