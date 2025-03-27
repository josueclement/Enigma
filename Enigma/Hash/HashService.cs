using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.Hash;

/// <summary>
/// Hash service
/// </summary>
public class HashService(Func<IDigest> digestFactory) : IHashService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;

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