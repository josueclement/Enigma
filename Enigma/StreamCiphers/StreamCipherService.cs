using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;
using System.Buffers;
using System.Threading;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service
/// </summary>
public class StreamCipherService : IStreamCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamCipherService"/> class using a custom cipher factory
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bufferSize">Buffer size. Default is 4096 bytes (4kB)</param>
    public StreamCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096)
    {
        _cipherFactory = cipherFactory;
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }
    
    /// <inheritdoc />
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Create and initialize the cipher
        var cipher = _cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);
        
        // Create a cipher stream for encryption
        using var cipherStream = new CipherStream(output, readCipher: null, writeCipher: cipher);
        
        // Rent a buffer from the pool
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            long totalBytesProgress = 0;
            
            // Read from the input stream
            while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                // Write to the cipher stream
                await cipherStream.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                
                // Report progress
                totalBytesProgress += bytesRead;
                progress?.Report(totalBytesProgress);
            }
            
            // Flush the cipher stream
            await cipherStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear the buffer and return it to the pool
            Array.Clear(buffer, 0, buffer.Length);
            _arrayPool.Return(buffer);
        }
    }

    /// <inheritdoc />
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Create and initialize the cipher
        var cipher = _cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);
        
        // Create a cipher stream for decryption
        using var cipherStream = new CipherStream(input, readCipher: cipher, writeCipher: null);
        
        // Rent a buffer from the pool
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            long totalBytesProgress = 0;
            
            // Read from the cipher stream
            while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                // Write to the output stream
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                
                // Report progress
                totalBytesProgress += bytesRead;
                progress?.Report(totalBytesProgress);
            }
            
            // Flush the output stream
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Clear the buffer and return it to the pool
            Array.Clear(buffer, 0, buffer.Length);
            _arrayPool.Return(buffer);
        }
    }
}