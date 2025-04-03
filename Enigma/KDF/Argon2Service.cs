using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.KDF;

/// <summary>
/// Argon2 PBE algorithm service
/// </summary>
public class Argon2Service
{
    /// <summary>
    /// Generate key
    /// </summary>
    /// <param name="size">Key size</param>
    /// <param name="passwordBytes">Password bytes</param>
    /// <param name="salt">Salt</param>
    /// <param name="iterations">Iterations</param>
    /// <param name="parallelism">Parallelism</param>
    /// <param name="memoryPowOfTwo">memory power of two</param>
    /// <returns></returns>
    public byte[] GenerateKey(
        int size,
        byte[] passwordBytes,
        byte[] salt,
        int iterations = 10,
        int parallelism = 4,
        int memoryPowOfTwo = 16)
    {
        var argon2Params = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithVersion(Argon2Parameters.Version13)
            .WithIterations(iterations)
            .WithMemoryPowOfTwo(memoryPowOfTwo)
            .WithParallelism(parallelism)
            .WithSalt(salt)
            .Build();
            
        var argon2Gen = new Argon2BytesGenerator();
        argon2Gen.Init(argon2Params);

        var derivedKey = new byte[size];
        
        argon2Gen.GenerateBytes(passwordBytes, derivedKey, 0, derivedKey.Length);
        
        return derivedKey;
    }
}