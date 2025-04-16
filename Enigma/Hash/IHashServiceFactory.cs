namespace Enigma.Hash;

/// <summary>
/// Definition for hash service factory
/// </summary>
public interface IHashServiceFactory
{
    /// <summary>
    /// Create a hash service with MD5 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateMd5Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create a hash service with SHA1 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha1Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create a hash service with SHA3 digest
    /// </summary>
    /// <param name="bitLength">Bit length</param>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha3Service(int bitLength = 512, int bufferSize = 4096);
    
    /// <summary>
    /// Create a hash service with SHA256 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha256Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create a hash service with SHA512 digest
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IHashService CreateSha512Service(int bufferSize = 4096);
}