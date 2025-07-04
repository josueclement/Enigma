namespace Enigma.Cryptography.Hash;

/// <summary>
/// Factory interface for creating various hash algorithm services.
/// </summary>
public interface IHashServiceFactory
{
    /// <summary>
    /// Creates a hash service that uses the MD5 hashing algorithm.
    /// MD5 produces a 128-bit (16-byte) hash value, typically expressed as a 32-digit hexadecimal number.
    /// Note: MD5 is no longer considered cryptographically secure and should not be used for security-critical applications.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer in bytes for processing data. Default is 4096 bytes (4KB).</param>
    /// <returns>An <see cref="IHashService"/> instance configured to use the MD5 algorithm.</returns>
    IHashService CreateMd5Service(int bufferSize = 4096);
    
    /// <summary>
    /// Creates a hash service that uses the SHA-1 hashing algorithm.
    /// SHA-1 produces a 160-bit (20-byte) hash value, typically expressed as a 40-digit hexadecimal number.
    /// Note: SHA-1 is no longer considered cryptographically secure for certain applications.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer in bytes for processing data. Default is 4096 bytes (4KB).</param>
    /// <returns>An <see cref="IHashService"/> instance configured to use the SHA-1 algorithm.</returns>
    IHashService CreateSha1Service(int bufferSize = 4096);
    
    /// <summary>
    /// Creates a hash service that uses the SHA-3 hashing algorithm.
    /// SHA-3 is the latest member of the Secure Hash Algorithm family, designed to be more resilient 
    /// against attacks that compromise other hash functions.
    /// </summary>
    /// <param name="bitLength">The output size of the hash in bits. Common values are 224, 256, 384, or 512. Default is 512 bits.</param>
    /// <param name="bufferSize">Size of the internal buffer in bytes for processing data. Default is 4096 bytes (4KB).</param>
    /// <returns>An <see cref="IHashService"/> instance configured to use the SHA-3 algorithm with specified bit length.</returns>
    IHashService CreateSha3Service(int bitLength = 512, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a hash service that uses the SHA-256 hashing algorithm.
    /// SHA-256 is part of the SHA-2 family and produces a 256-bit (32-byte) hash value,
    /// typically expressed as a 64-digit hexadecimal number.
    /// This algorithm provides stronger security than SHA-1 and is widely used in security applications.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer in bytes for processing data. Default is 4096 bytes (4KB).</param>
    /// <returns>An <see cref="IHashService"/> instance configured to use the SHA-256 algorithm.</returns>
    IHashService CreateSha256Service(int bufferSize = 4096);
    
    /// <summary>
    /// Creates a hash service that uses the SHA-512 hashing algorithm.
    /// SHA-512 is part of the SHA-2 family and produces a 512-bit (64-byte) hash value,
    /// typically expressed as a 128-digit hexadecimal number.
    /// This algorithm provides the highest security level among the standard SHA-2 variants.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer in bytes for processing data. Default is 4096 bytes (4KB).</param>
    /// <returns>An <see cref="IHashService"/> instance configured to use the SHA-512 algorithm.</returns>
    IHashService CreateSha512Service(int bufferSize = 4096);
}
