using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.Buffers;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Provides cryptographic operations for block ciphers
/// </summary>
public class BlockCipherService : IBlockCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    /// <summary>
    /// Initializes a new instance of the <see cref="BlockCipherService"/> class using a custom cipher factory
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bufferSize">Buffer size. Default is 4096 bytes (4kB)</param>
    public BlockCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096)
    {
        _cipherFactory = cipherFactory;
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="BlockCipherService"/> class using a standard algorithm name
    /// </summary>
    /// <param name="algorithmName">Algorithm name</param>
    /// <param name="bufferSize">Buffer size. Default is 4096 bytes (4kB)</param>
    /// <remarks>
    /// <para>
    /// Algorithm name examples:
    /// <list type="bullet">
    ///   <item><description>AES/GCM/NoPadding</description></item>
    ///   <item><description>AES/CBC/PKCS7Padding</description></item>
    /// </list>
    /// </para>
    /// </remarks>
    public BlockCipherService(string algorithmName, int bufferSize = 4096)
        : this(() => CipherUtilities.GetCipher(algorithmName), bufferSize) { }
    
    /// <inheritdoc />
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        await EncryptStreamAsync(input, output, cipher, progress, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        await DecryptStreamAsync(input, output, cipher, progress, cancellationToken).ConfigureAwait(false);
    }

    private async Task EncryptStreamAsync(
        Stream input,
        Stream output,
        IBufferedCipher cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        using var cipherStream = new CipherStream(output, null, cipher);
        var buffer = _arrayPool.Rent(_bufferSize);
        
        try
        {
            int bytesRead;
            long totalBytesProgress = 0;
            
            while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                await cipherStream.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);

                totalBytesProgress += bytesRead;
                progress?.Report(totalBytesProgress);
            }

            await cipherStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(buffer, 0, buffer.Length);
            _arrayPool.Return(buffer);
        }
    }

    private async Task DecryptStreamAsync(
        Stream input,
        Stream output,
        IBufferedCipher cipher,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        using var cipherStream = new CipherStream(input, cipher, null);
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            long totalBytesProgress = 0;
            
            while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                
                totalBytesProgress += bytesRead;
                progress?.Report(totalBytesProgress);
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