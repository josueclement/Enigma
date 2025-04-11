using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher services
/// </summary>
public interface IBlockCipherService
{
    /// <summary>
    /// Asynchronously encrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters);
    
    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters);
}