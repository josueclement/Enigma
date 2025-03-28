using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for block cipher services
/// </summary>
public interface IBlockCipherService
{
    /// <summary>
    /// Get key and IV size
    /// </summary>
    /// <returns>(key size, IV size)</returns>
    (int keySizeInBytes, int ivSizeInBytes) GetKeyIvSize();
    
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