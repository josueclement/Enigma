namespace Enigma;

/// <summary>
/// Definition for stream cipher service factory
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Create ChaCha20Rfc7539 stream cipher service
    /// </summary>
    IStreamCipherService CreateChaCha20Rfc7539StreamCipherService();
    
    /// <summary>
    /// Create ChaCha20 stream cipher service
    /// </summary>
    IStreamCipherService CreateChaCha20StreamCipherService();
    
    /// <summary>
    /// Create Salsa20 stream cipher service
    /// </summary>
    IStreamCipherService CreateSalsa20StreamCipherService();
}