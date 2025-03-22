using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for stream ciphers services
/// </summary>
public interface IStreamCipherService
{
    /// <summary>
    /// Encrypt data
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    /// <returns>Encrypted data</returns>
    byte[] Encrypt(byte[] data, byte[] key, byte[] nonce);
    
    /// <summary>
    /// Decrypt data
    /// </summary>
    /// <param name="data">Data to decrypt</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    /// <returns>Decrypted data</returns>
    byte[] Decrypt(byte[] data, byte[] key, byte[] nonce);

    /// <summary>
    /// Asynchronously encrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    // TODO: Cancellation token
    Task EncryptStreamAsync(Stream input, Stream output, byte[] key, byte[] nonce);
    
    /// <summary>
    /// Asynchronously decrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    // TODO: Cancellation token
    Task DecryptStreamAsync(Stream input, Stream output, byte[] key, byte[] nonce);
}