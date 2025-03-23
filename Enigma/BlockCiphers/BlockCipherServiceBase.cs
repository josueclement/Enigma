using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using Enigma.Utils;

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
    /// <returns><see cref="IBufferedCipher"/></returns>
    protected abstract IBufferedCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv);

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
    public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        var cipher = BuildCipher(forEncryption: true, key, iv);
        var enc = new byte[data.Length];
        cipher.ProcessBytes(data, enc, 0);
        return enc; 
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
    {
        var cipher = BuildCipher(forEncryption: false, key, iv);
        var dec = new byte[data.Length];
        cipher.ProcessBytes(data, dec, 0);
        return dec; 
    }

    /// <inheritdoc />
    public async Task EncryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv)
    {
        
    }

    /// <inheritdoc />
    public async Task DecryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv)
    {
        
    }
}