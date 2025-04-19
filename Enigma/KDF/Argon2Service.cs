using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.KDF;

/// <summary>
/// Service for password-based key derivation using the Argon2id algorithm.
/// Argon2 is a memory-hard password hashing function designed to be resistant to
/// GPU, ASIC, and side-channel attacks.
/// </summary>
/// <remarks>
/// This implementation uses BouncyCastle's Argon2BytesGenerator with the Argon2id variant,
/// which combines the security benefits of Argon2i and Argon2d.
/// </remarks>
public class Argon2Service
{
    /// <summary>
    /// Generates a cryptographic key using the Argon2id password-based key derivation function.
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
    /// <returns>The derived key as a byte array of the specified size.</returns>
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