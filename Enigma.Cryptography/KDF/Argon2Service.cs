using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Cryptography.KDF;

/// <summary>
/// Service for password-based key derivation using the Argon2 algorithm family.
/// Argon2 is a memory-hard password hashing function designed to be resistant to
/// GPU, ASIC, and side-channel attacks.
/// </summary>
/// <remarks>
/// This implementation uses BouncyCastle's Argon2BytesGenerator which supports all
/// Argon2 variants (Argon2d, Argon2i, and Argon2id) configurable through parameters.
/// </remarks>
public class Argon2Service
{
    /// <summary>
    /// Generates a cryptographic key using the Argon2 password-based key derivation function.
    /// </summary>
    /// <param name="size">The size of the derived key in bytes.</param>
    /// <param name="passwordBytes">The password bytes to derive the key from.</param>
    /// <param name="salt">
    /// The cryptographic salt to use. Salt should be random and unique for each password.
    /// Recommended minimum size is 16 bytes.
    /// </param>
    /// <param name="iterations">
    /// The number of iterations to perform (time cost parameter).
    /// Higher values increase security but also computation time. Default is 10.
    /// </param>
    /// <param name="parallelism">
    /// The degree of parallelism to use (threads to use).
    /// Higher values can improve performance on multi-core systems. Default is 4.
    /// </param>
    /// <param name="memoryPowOfTwo">
    /// The memory size to use as power of 2 (memory cost parameter).
    /// Memory used will be 2^memoryPowOfTwo KiB. Default is 16 (64 MiB).
    /// Higher values increase security but also memory usage.
    /// </param>
    /// <param name="argon2Variant">
    /// The Argon2 variant to use. Default is Argon2id (0x02).
    /// <list type="bullet">
    /// <item><description>0x00: Argon2d - Provides the highest resistance against GPU cracking attacks</description></item>
    /// <item><description>0x01: Argon2i - Provides protection against side-channel attacks</description></item>
    /// <item><description>0x02: Argon2id - Hybrid mode that combines Argon2i and Argon2d approaches</description></item>
    /// </list>
    /// </param>
    /// <param name="argon2Version">
    /// The Argon2 version to use. Default is Argon2 1.3 (0x13).
    /// <list type="bullet">
    /// <item><description>0x10: Argon2 1.0</description></item>
    /// <item><description>0x13: Argon2 1.3</description></item>
    /// </list>
    /// </param>
    /// <returns>The derived key as a byte array of the specified size.</returns>
    public byte[] GenerateKey(
        int size,
        byte[] passwordBytes,
        byte[] salt,
        int iterations = 10,
        int parallelism = 4,
        int memoryPowOfTwo = 16,
        int argon2Variant = 0x02,
        int argon2Version = 0x13)
    {
        var argon2Params = new Argon2Parameters.Builder(argon2Variant)
            .WithVersion(argon2Version)
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