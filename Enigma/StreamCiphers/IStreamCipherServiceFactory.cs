namespace Enigma.StreamCiphers;

/// <summary>
/// Definition for stream cipher service factory
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Create ChaCha20Rfc7539 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IStreamCipherService CreateChaCha7539Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create ChaCha20 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IStreamCipherService CreateChaCha20Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create Salsa20 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Buffer size</param>
    IStreamCipherService CreateSalsa20Service(int bufferSize = 4096);
}