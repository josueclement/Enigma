using System;
using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma;

/// <summary>
/// Hash service
/// </summary>
public class HashService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;

    private readonly Func<IDigest> _digestFactory;
    
    /// <summary>
    /// Constructor for <see cref="HashService"/>
    /// </summary>
    public HashService(Func<IDigest> digestFactory)
    {
        _digestFactory = digestFactory;
    }
    
    /// <summary>
    /// Hash data
    /// </summary>
    /// <param name="data">Data to hash</param>
    /// <returns>Hash</returns>
    public byte[] Hash(byte[] data)
    {
        var digest = _digestFactory();
        var hash = new byte[digest.GetDigestSize()];

        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(hash, 0);

        return hash;
    }

    /// <summary>
    /// Asynchronously hash input stream data
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <returns>Hash</returns>
    public async Task<byte[]> HashAsync(Stream input)
    {
        var digest = _digestFactory();
        var hash = new byte[digest.GetDigestSize()];

        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);
            if (bytesRead > 0)
                digest.BlockUpdate(buffer, 0, bytesRead);
        } while (bytesRead == BUFFER_SIZE);

        digest.DoFinal(hash, 0);

        return hash;
    }
}