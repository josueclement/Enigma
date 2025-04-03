using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.PQC;

/// <summary>
/// Module-Lattice-Based key-encapsulation mechanism (ML-KEM) service
/// </summary>
/// <param name="parametersFactory">Parameters factory</param>
public class MLKemService(
    Func<MLKemParameters> parametersFactory) : IMLKemService
{
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), parametersFactory()));
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public (byte[] encapsulation, byte[] secret) Encapsulate(AsymmetricKeyParameter publicKey)
    {
        var encapsulator = new MLKemEncapsulator(parametersFactory());
        encapsulator.Init(publicKey);
        var encapsulation = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(encapsulation, 0, encapsulation.Length, secret, 0, secret.Length);
        return (encapsulation, secret);
    }

    /// <inheritdoc />
    public byte[] Decapsulate(AsymmetricKeyParameter privateKey, byte[] encapsulation)
    {
        var decapsulator = new MLKemDecapsulator(parametersFactory());
        decapsulator.Init(privateKey);
        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(encapsulation, 0, encapsulation.Length, secret, 0, secret.Length);
        return secret;
    }
}