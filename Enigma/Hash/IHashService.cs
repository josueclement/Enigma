using System.IO;
using System.Threading.Tasks;
using System.Threading;
using System;

namespace Enigma.Hash;

/// <summary>
/// Defines operations for generating cryptographic hash values from input data.
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Asynchronously computes a hash value for the data in the provided stream.
    /// </summary>
    /// <param name="input">The input stream containing data to be hashed. The stream will be read from its current position.</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the computed hash as a byte array.</returns>
    Task<byte[]> HashAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}