using System;
using System.IO;
using System.Text;
using Enigma.PublicKey;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Enigma.Utils;

/// <summary>
/// Pem utilities
/// </summary>
public static class PemUtils
{
   /// <summary>
    /// Save key in PEM format
    /// </summary>
    /// <param name="key">Key to save</param>
    /// <param name="output">Output stream</param>
    public static void SaveKey(AsymmetricKeyParameter key, Stream output)
    {
        using var writer = new StreamWriter(output, Encoding.UTF8);
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(key);
    }

    /// <summary>
    /// Encrypt and save private key in PEM format
    /// </summary>
    /// <param name="privateKey">Private key to save</param>
    /// <param name="output">Output stream</param>
    /// <param name="password">Password for key encryption</param>
    /// <param name="algorithm">Algorithm for key encryption</param>
    public static void SavePrivateKey(AsymmetricKeyParameter privateKey, Stream output,
        string password, string algorithm = "AES-256-CBC")
    {
        using var writer = new StreamWriter(output, Encoding.UTF8);
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(privateKey, algorithm, password.ToCharArray(), new SecureRandom());
    }

    /// <summary>
    /// Load key from PEM
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <returns>Key</returns>
    public static AsymmetricKeyParameter LoadKey(Stream input)
    {
        using var reader = new StreamReader(input, Encoding.UTF8);
        var pemReader = new PemReader(reader);
        var obj = pemReader.ReadObject();

        return obj switch
        {
            AsymmetricKeyParameter key => key,
            _ => throw new InvalidOperationException("No AsymmetricKeyParameter found in Pem")
        };
    }

    /// <summary>
    /// Load private key from PEM
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="password">Password for key decryption</param>
    /// <returns>Key</returns>
    public static AsymmetricKeyParameter LoadPrivateKey(Stream input, string password)
    {
        using var reader = new StreamReader(input, Encoding.UTF8);
        var pemReader = new PemReader(reader, new PemPasswordFinder(password));
        var obj = pemReader.ReadObject();

        return obj switch
        {
            AsymmetricCipherKeyPair keyPair => keyPair.Private,
            AsymmetricKeyParameter { IsPrivate: true } key => key,
            _ => throw new InvalidOperationException("No private key found in Pem")
        };
    } 
}