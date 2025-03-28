namespace Enigma;

/// <summary>
/// Definition for hash service factory
/// </summary>
public interface IHashServiceFactory
{
    /// <summary>
    /// Create a hash service with MD5 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateMd5HashService(int bufferSize);
    
    /// <summary>
    /// Create a hash service with SHA1 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha1HashService(int bufferSize);
    
    /// <summary>
    /// Create a hash service with SHA3 digest
    /// </summary>
    /// <param name="bitLength">Bit length</param>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha3HashService(int bitLength, int bufferSize);
    
    /// <summary>
    /// Create a hash service with SHA256 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha256HashService(int bufferSize);
    
    /// <summary>
    /// Create a hash service with SHA512 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha512HashService(int bufferSize);
}