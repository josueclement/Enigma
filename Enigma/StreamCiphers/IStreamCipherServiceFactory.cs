namespace Enigma.StreamCiphers;

/// <summary>
/// Factory interface for creating stream cipher encryption/decryption services.
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Create ChaCha20Rfc7539 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured stream cipher service ready for encryption/decryption operations.</returns>
    IStreamCipherService CreateChaCha7539Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create ChaCha20 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured stream cipher service ready for encryption/decryption operations.</returns>
    IStreamCipherService CreateChaCha20Service(int bufferSize = 4096);
    
    /// <summary>
    /// Create Salsa20 stream cipher service
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured stream cipher service ready for encryption/decryption operations.</returns>
    IStreamCipherService CreateSalsa20Service(int bufferSize = 4096);
}