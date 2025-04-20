using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.PQC;

/// <summary>
/// Provides cryptographic operations for the Module-Lattice-Based Key Encapsulation Mechanism (ML-KEM).
/// ML-KEM is a post-quantum cryptographic algorithm designed to be secure against quantum computer attacks.
/// This service encapsulates key generation, encapsulation, and decapsulation operations using the BouncyCastle 
/// cryptographic library implementation.
/// </summary>
/// <remarks>
/// The implementation uses the specified ML-KEM parameters factory to configure the underlying cryptographic operations.
/// ML-KEM (previously known as Kyber) is a NIST-standardized post-quantum key encapsulation mechanism.
/// </remarks>
/// <param name="parametersFactory">Factory function that provides ML-KEM parameters for cryptographic operations</param>
// ReSharper disable once InconsistentNaming
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
    public byte[] Decapsulate(byte[] encapsulation, AsymmetricKeyParameter privateKey)
    {
        var decapsulator = new MLKemDecapsulator(parametersFactory());
        decapsulator.Init(privateKey);
        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(encapsulation, 0, encapsulation.Length, secret, 0, secret.Length);
        return secret;
    }
}