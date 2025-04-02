using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based digital signature algorithm (ML-DSA) service
/// </summary>
/// <param name="keyPairGeneratorFactory"></param>
/// <param name="signerFactory"></param>
public class ModuleLatticeBasedDsaService(
    Func<IAsymmetricCipherKeyPairGenerator> keyPairGeneratorFactory,
    Func<MLDsaParameters> parametersFactory,
    Func<ISigner> signerFactory) : IModuleLatticeBasedDsaService
{
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var generator = keyPairGeneratorFactory();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), parametersFactory()));
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
    {
        var signer = signerFactory();
        signer.Init(forSigning: true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
    {
        var signer = signerFactory();
        signer.Init(forSigning: false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}
//TODO: Key-Encapsulation Mechanism
