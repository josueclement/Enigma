using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Provides cryptographic services for block cipher operations. This interface defines methods
/// for encrypting and decrypting data using block ciphers with configurable parameters,
/// supporting asynchronous operations with progress reporting and cancellation capabilities.
/// </summary>
public interface IBlockCipherService
{
    /// <summary>
    /// Encrypts data from the input stream to the output stream using the specified cipher parameters
    /// </summary>
    /// <param name="input">The input stream containing the plaintext data</param>
    /// <param name="output">The output stream where encrypted data will be written</param>
    /// <param name="cipherParameters">The parameters to initialize the cipher</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation</param>
    /// <returns>A task representing the asynchronous encryption operation</returns>
    Task EncryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Decrypts data from the input stream to the output stream using the specified cipher parameters
    /// </summary>
    /// <param name="input">The input stream containing the encrypted data</param>
    /// <param name="output">The output stream where decrypted data will be written</param>
    /// <param name="cipherParameters">The parameters to initialize the cipher</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation</param>
    /// <returns>A task representing the asynchronous decryption operation</returns>
    Task DecryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}