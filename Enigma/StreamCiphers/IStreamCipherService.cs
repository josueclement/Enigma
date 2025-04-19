using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.StreamCiphers;

/// <summary>
/// Provides cryptographic services for stream cipher operations. This interface defines methods
/// for encrypting and decrypting data using stream ciphers with configurable parameters,
/// supporting asynchronous operations with progress reporting and cancellation capabilities.
/// </summary>
public interface IStreamCipherService
{
    /// <summary>
    /// Encrypts data from the input stream to the output stream using the specified key and nonce.
    /// </summary>
    /// <param name="input">The input stream containing the plaintext data</param>
    /// <param name="output">The output stream where encrypted data will be written</param>
    /// <param name="key">The secret key used for encryption/decryption</param>
    /// <param name="nonce">Number used once that must be unique for each encryption with the same key</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation</param>
    /// <returns>A task representing the asynchronous encryption operation</returns>
    Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Decrypts data from the input stream to the output stream using the specified key and nonce.
    /// </summary>
    /// <param name="input">The input stream containing the encrypted data</param>
    /// <param name="output">The output stream where decrypted data will be written</param>
    /// <param name="key">The secret key used for encryption/decryption</param>
    /// <param name="nonce">Number used once that must be unique for each encryption with the same key</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation</param>
    /// <returns>A task representing the asynchronous decryption operation</returns>
    Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default);
}