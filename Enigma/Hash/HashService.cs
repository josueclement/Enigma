using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.Hash;

/// <summary>
/// Hash service
/// </summary>
/// <param name="digestFactory">Digest factory</param>
/// <param name="bufferSize">Buffer size</param>
public class HashService(Func<IDigest> digestFactory, int bufferSize = 4096) : IHashService
{
    /// <inheritdoc />
    public byte[] Hash(byte[] data)
    {
        var digest = digestFactory();
        var hash = new byte[digest.GetDigestSize()];

        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(hash, 0);

        return hash;
    }

    /// <inheritdoc />
    public async Task<byte[]> HashAsync(Stream input)
    {
        var digest = digestFactory();
        var buffer = new byte[bufferSize];
        int bytesRead;
    
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            digest.BlockUpdate(buffer, 0, bytesRead);
    
        var hash = new byte[digest.GetDigestSize()];
    
        digest.DoFinal(hash, 0);
    
        return hash;
    }
}