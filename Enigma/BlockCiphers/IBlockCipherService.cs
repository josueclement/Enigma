using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

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
    Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters);
    
    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters);
}