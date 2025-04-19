using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System.Threading.Tasks;
using System;
using System.Buffers;
using System.Threading;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service
/// </summary>
public class BlockCipherService : IBlockCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bufferSize">Buffer size</param>
    public BlockCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096)
    {
        _cipherFactory = cipherFactory;
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="algorithmName"></param>
    /// <param name="bufferSize"></param>
    public BlockCipherService(string algorithmName, int bufferSize = 4096)
        : this(() => CipherUtilities.GetCipher(algorithmName), bufferSize) { }
    
    
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, CancellationToken cancellationToken = default)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        await EncryptStreamAsync(input, output, cipher, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, CancellationToken cancellationToken = default)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        await DecryptStreamAsync(input, output, cipher, cancellationToken).ConfigureAwait(false);
    }

    private async Task EncryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        using var cipherStream = new CipherStream(output, null, cipher);
        var buffer = _arrayPool.Rent(_bufferSize);
        try
        {
            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await cipherStream.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
            }

            await cipherStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(buffer, 0, buffer.Length);
            _arrayPool.Return(buffer);
        }
    }

    private async Task DecryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        using var cipherStream = new CipherStream(input, cipher, null);
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(buffer, 0, buffer.Length);
            _arrayPool.Return(buffer);
        }
    }
}