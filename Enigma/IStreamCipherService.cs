using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for stream ciphers services
/// </summary>
public interface IStreamCipherService
{
    /// <summary>
    /// Key size
    /// </summary>
    int KeySize { get; }
    
    /// <summary>
    /// Nonce size
    /// </summary>
    int NonceSize { get; }
    
    /// <summary>
    /// Generate random key and nonce
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    void GenerateKeyNonce(out byte[] key, out byte[] nonce);
    
    /// <summary>
    /// Asynchronously encrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
    
    /// <summary>
    /// Asynchronously decrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
}