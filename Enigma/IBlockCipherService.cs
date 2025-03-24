using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for block ciphers services
/// </summary>
public interface IBlockCipherService
{
    /// <summary>
    /// Asynchronously encrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    /// <param name="padding">Padding</param>
    // TODO: Cancellation token
    Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding);
    
    /// <summary>
    /// Asynchronously decrypt stream
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    /// <param name="padding">Padding</param>
    // TODO: Cancellation token
    Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding);
}