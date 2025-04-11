using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service
/// </summary>
public class BlockCipherService : IBlockCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bufferSize">Buffer size</param>
    public BlockCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096)
    {
        _cipherFactory = cipherFactory;
        _bufferSize = bufferSize;
    }

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="algorithmName"></param>
    /// <param name="bufferSize"></param>
    public BlockCipherService(string algorithmName, int bufferSize = 4096)
        : this(() => CipherUtilities.GetCipher(algorithmName), bufferSize) { }
    
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        await EncryptStreamAsync(input, output, cipher).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        await DecryptStreamAsync(input, output, cipher).ConfigureAwait(false);
    }

    private async Task EncryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher)
    {
        using var cipherStream = new CipherStream(output, null, cipher);
        var buffer = new byte[_bufferSize];
        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            await cipherStream.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
        }
    }

    private async Task DecryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher)
    {
        using var cipherStream = new CipherStream(input, cipher, null);
        var buffer = new byte[_bufferSize];
        int bytesRead;
        while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            await output.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
        } 
    }
}