using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.KDF;

/// <summary>
/// PBKDF2 service
/// </summary>
public class Pbkdf2Service
{
    /// <summary>
    /// Generate key
    /// </summary>
    /// <param name="size">Key size</param>
    /// <param name="password">Password</param>
    /// <param name="salt">Salt</param>
    /// <param name="iterations">Iterations</param>
    /// <returns>Key data</returns>
    public byte[] GenerateKey(int size, string password, byte[] salt, int iterations = 10_000)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var generator = new Pkcs5S2ParametersGenerator();
        generator.Init(passwordBytes, salt, iterations);

        var keyParameter = (KeyParameter)generator.GenerateDerivedParameters("AES", size * 8);
        return keyParameter.GetKey(); 
    }
}