using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma;

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
    /// <param name="padding">Padding</param>
    Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, IPaddingService padding);
    
    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    /// <param name="padding">Padding</param> 
    Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, IPaddingService padding);
}