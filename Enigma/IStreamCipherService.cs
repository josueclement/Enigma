using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for stream cipher services
/// </summary>
public interface IStreamCipherService
{
    /// <summary>
    /// Asynchronously encrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
    
    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param> 
    Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce);
}