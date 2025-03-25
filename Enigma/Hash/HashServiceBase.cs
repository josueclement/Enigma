using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Hash;

/// <summary>
/// Hash service base class
/// </summary>
public abstract class HashServiceBase : IHashService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <inheritdoc />
    public abstract int HashSize { get; }
    
    /// <summary>
    /// Abstract digest factory method
    /// </summary>
    /// <returns>Digest</returns>
    protected abstract IDigest BuildDigest();
    
    /// <inheritdoc />
    public byte[] Hash(byte[] data)
    {
        var hash = new byte[HashSize];

        var digest = BuildDigest();
        digest.BlockUpdate(data, 0, data.Length);
        digest.DoFinal(hash, 0);

        return hash;
    }

    /// <inheritdoc />
    public async Task<byte[]> HashAsync(Stream input)
    {
        var hash = new byte[HashSize];

        var hasher = BuildDigest();
        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);
            if (bytesRead > 0)
                hasher.BlockUpdate(buffer, 0, bytesRead);
        } while (bytesRead == BUFFER_SIZE);

        hasher.DoFinal(hash, 0);

        return hash;
    }
}