using System;
using System.IO;
using System.Text;
using Enigma.PublicKey;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Enigma;

/// <summary>
/// PEM extensions for <see cref="IPublicKeyService"/>
/// </summary>
// ReSharper disable once InconsistentNaming
public static class IPublicKeyServicePemExtensions
{
    /// <summary>
    /// Save key in PEM format
    /// </summary>
    /// <param name="service">Public-key service</param>
    /// <param name="key">Key to save</param>
    /// <param name="output">Output stream</param>
    public static void SaveKey(this IPublicKeyService service, AsymmetricKeyParameter key, Stream output)
    {
        using var writer = new StreamWriter(output, Encoding.UTF8);
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(key);
    }

    /// <summary>
    /// Encrypt and save private key in PEM format
    /// </summary>
    /// <param name="service">Public-key service</param>
    /// <param name="privateKey">Private key to save</param>
    /// <param name="output">Output stream</param>
    /// <param name="password">Password for key encryption</param>
    /// <param name="algorithm">Algorithm for key encryption</param>
    public static void SavePrivateKey(this IPublicKeyService service, AsymmetricKeyParameter privateKey, Stream output,
        string password, string algorithm = "AES-256-CBC")
    {
        using var writer = new StreamWriter(output, Encoding.UTF8);
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(privateKey, algorithm, password.ToCharArray(), new SecureRandom());
    }

    /// <summary>
    /// Load key from PEM
    /// </summary>
    /// <param name="service">Public-key service</param>
    /// <param name="input">Input stream</param>
    /// <returns>Key</returns>
    public static AsymmetricKeyParameter LoadKey(this IPublicKeyService service, Stream input)
    {
        using var reader = new StreamReader(input, Encoding.UTF8);
        var pemReader = new PemReader(reader);
        object obj = pemReader.ReadObject();

        if (obj is AsymmetricKeyParameter key)
            return key;
        
        throw new InvalidOperationException("No AsymmetricKeyParameter found in Pem");
    }

    /// <summary>
    /// Load private key from PEM
    /// </summary>
    /// <param name="service">Public-key service</param>
    /// <param name="input">Input stream</param>
    /// <param name="password">Password for key decryption</param>
    /// <returns>Key</returns>
    public static AsymmetricKeyParameter LoadPrivateKey(this IPublicKeyService service, Stream input, string password)
    {
        using var reader = new StreamReader(input, Encoding.UTF8);
        var pemReader = new PemReader(reader, new PemPasswordFinder(password));
        object obj = pemReader.ReadObject();

        if (obj is AsymmetricCipherKeyPair keyPair)
            return keyPair.Private;
        
        throw new InvalidOperationException("No AsymmetricCipherKeyPair found in Pem");
    }
}