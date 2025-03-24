using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for stream ciphers services
/// </summary>
public interface IStreamCipherService
{
    /// <summary>
    /// Asynchronously encrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    // TODO: Cancellation token
    Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
    
    /// <summary>
    /// Asynchronously decrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    // TODO: Cancellation token
    Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
}