using Org.BouncyCastle.Crypto;
using System.Buffers;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.Cryptography.Hash;

/// <summary>
/// Provides hash computation services for streams.
/// </summary>
public class HashService : IHashService
{
    private readonly Func<IDigest> _digestFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="HashService"/> class.
    /// </summary>
    /// <param name="digestFactory">Factory function that creates the cryptographic digest algorithm to use.</param>
    /// <param name="bufferSize">Size of the buffer used for reading from input streams. Default is 4096 bytes.</param>
    public HashService(Func<IDigest> digestFactory, int bufferSize = 4096)
    {
        _digestFactory = digestFactory;
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }
    
    /// <inheritdoc />
    public async Task<byte[]> HashAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        // Create and initialize the digest
        var digest = _digestFactory();
        
        // Rent a buffer from the pool
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;

            // Read from the input stream
            while ((bytesRead = await input.ReadAsync(buffer, 0, _bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                
                // Update the digest with the read data
                digest.BlockUpdate(buffer, 0, bytesRead);
                
                // Report progress
                progress?.Report(bytesRead);
            }

            // Compute and return the hash
            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }
        finally
        {
            // Return the buffer to the pool and clear it
            _arrayPool.Return(buffer, clearArray: true);
        }

    }
}