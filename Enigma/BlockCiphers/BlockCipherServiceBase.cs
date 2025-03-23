using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher base class
/// </summary>
public abstract class BlockCipherServiceBase : IBlockCipherService
{
    /// <summary>
    /// Gets key size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int KeySize { get; }
    
    /// <summary>
    /// Gets IV size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int IvSize { get; }
    
    /// <summary>
    /// Gets block size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int BlockSize { get; }
    
    /// <summary>
    /// Abstract cipher factory method
    /// </summary>
    /// <param name="forEncryption">True for encryption, False for decryption</param>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    /// <returns>Cipher</returns>
    protected abstract BufferedBlockCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv);

    /// <summary>
    /// Generate random key and IV
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    public void GenerateKeyIv(out byte[] key, out byte[] iv)
    {
        key = RandomUtils.GenerateRandomBytes(KeySize);
        iv = RandomUtils.GenerateRandomBytes(IvSize);
    }

    /// <inheritdoc />
    public async Task EncryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding)
    {
        var cipher = BuildCipher(true, key, iv);
        await ProcessStreamAsync(input, output, cipher, padding);
    }

    /// <inheritdoc />
    public async Task DecryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding)
    {
        var cipher = BuildCipher(false, key, iv);
        await ProcessStreamAsync(input, output, cipher, padding);
    }

    private async Task ProcessStreamAsync(Stream input, Stream output, BufferedBlockCipher cipher, IPaddingService padding)
    {
        
    }
}