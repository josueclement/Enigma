namespace Enigma.Cryptography.StreamCiphers;

/// <summary>
/// Factory interface for creating stream cipher encryption/decryption services.
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Creates a ChaCha20-RFC7539 stream cipher service implementation.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured ChaCha20-RFC7539 cipher service ready for encryption/decryption operations.</returns>
    /// <remarks>
    /// This implementation follows the RFC7539 standard, which specifies a 96-bit nonce and
    /// 32-bit counter, offering improved security and interoperability compared to the original ChaCha20.
    /// </remarks>
    IStreamCipherService CreateChaCha7539Service(int bufferSize = 4096);
    
    /// <summary>
    /// Creates a ChaCha20 stream cipher service implementation (original version).
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured ChaCha20 cipher service ready for encryption/decryption operations.</returns>
    /// <remarks>
    /// The original ChaCha20 uses a 64-bit nonce and 64-bit counter. Consider using the RFC7539 version
    /// for newer applications requiring standards compliance.
    /// </remarks>
    IStreamCipherService CreateChaCha20Service(int bufferSize = 4096);
    
    /// <summary>
    /// Creates a Salsa20 stream cipher service implementation.
    /// </summary>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured Salsa20 cipher service ready for encryption/decryption operations.</returns>
    /// <remarks>
    /// Salsa20 is the predecessor to ChaCha20, using a similar design but with different internal operations.
    /// It offers good performance and has undergone significant cryptanalysis.
    /// </remarks>
    IStreamCipherService CreateSalsa20Service(int bufferSize = 4096);
}