namespace Enigma;

/// <summary>
/// Definition for stream cipher service factory
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Create ChaCha20Rfc7539 stream cipher service
    /// </summary>
    IStreamCipherService CreateChaCha7539Service();
    
    /// <summary>
    /// Create ChaCha20 stream cipher service
    /// </summary>
    IStreamCipherService CreateChaCha20Service();
    
    /// <summary>
    /// Create Salsa20 stream cipher service
    /// </summary>
    IStreamCipherService CreateSalsa20Service();
}