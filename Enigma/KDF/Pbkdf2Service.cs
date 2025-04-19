using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace Enigma.KDF;

/// <summary>
/// Provides functionality for generating cryptographic keys using PBKDF2 (Password-Based Key Derivation Function 2).
/// </summary>
/// <remarks>
/// PBKDF2 is a key derivation function that is part of RSA's PKCS #5 v2.0 standard.
/// It applies a pseudorandom function (such as HMAC-SHA1) to the input password along with a salt value,
/// and repeats the process multiple times to produce a derived key, which can then be used as a cryptographic key.
/// 
/// This implementation uses the BouncyCastle library's PKCS5S2ParametersGenerator internally with SHA-1 as the default digest.
/// </remarks>
public class Pbkdf2Service
{
    /// <summary>
    /// Generates a cryptographic key using PBKDF2 with the specified parameters.
    /// </summary>
    /// <param name="size">The desired key size in bytes. Common values are 16 (128 bits), 24 (192 bits), or 32 (256 bits).</param>
    /// <param name="password">The password from which to derive the key. Should be sufficiently complex.</param>
    /// <param name="salt">
    /// The salt value to use in the derivation. 
    /// Should be at least 8 bytes of random data, and unique for each stored key.
    /// </param>
    /// <param name="iterations">
    /// The number of iterations to perform in the key derivation process.
    /// Higher values increase security but also computation time. Default is 10,000.
    /// NIST recommends at least 10,000 iterations, with higher values preferred for sensitive applications.
    /// </param>
    /// <returns>The derived key as a byte array of the requested size.</returns>
    /// <remarks>
    /// This method uses AES as the target algorithm for the derived key.
    /// The underlying implementation uses SHA-1 as the pseudorandom function.
    /// </remarks>
    public byte[] GenerateKey(int size, string password, byte[] salt, int iterations = 10_000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var generator = new Pkcs5S2ParametersGenerator();
        generator.Init(passwordBytes, salt, iterations);

        var keyParameter = (KeyParameter)generator.GenerateDerivedParameters("AES", size * 8);
        return keyParameter.GetKey(); 
    }
}