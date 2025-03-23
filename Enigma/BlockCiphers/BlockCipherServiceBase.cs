using Enigma.Utils;
using Org.BouncyCastle.Crypto.Paddings;
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
    /// <param name="padding">Padding</param>
    /// <returns><see cref="IBufferedCipher"/></returns>
    protected abstract PaddedBufferedBlockCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv, IBlockCipherPadding padding);

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
    public async Task EncryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv, IBlockCipherPadding padding)
    {
        var cipher = BuildCipher(true, key, iv, padding);
        await ProcessStreamAsync(input, output, cipher);
    }

    /// <inheritdoc />
    public async Task DecryptStreamAsync(Stream input, Stream output, byte[] key, byte[] iv, IBlockCipherPadding padding)
    {
        var cipher = BuildCipher(false, key, iv, padding);
        await ProcessStreamAsync(input, output, cipher);
    }

    private const int BUFFER_SIZE = 32;

    private async Task ProcessStreamAsync(Stream input, Stream output, PaddedBufferedBlockCipher cipher)
    {
        var buffer = new byte[BUFFER_SIZE];
        var outputBuffer = new byte[BUFFER_SIZE + BlockSize];
            
        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            var outputLen = cipher.ProcessBytes(buffer, 0, bytesRead, outputBuffer, 0);
            if (outputLen > 0)
            {
                await output.WriteAsync(outputBuffer, 0, outputLen);
            }
        }
            
        var outputLenFinal = cipher.DoFinal(outputBuffer, 0);
        if (outputLenFinal > 0)
        {
            await output.WriteAsync(outputBuffer, 0, outputLenFinal);
        }
    }
}