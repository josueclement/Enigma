using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.Hash;

/// <summary>
/// Hash service factory
/// </summary>
public class HashServiceFactory : IHashServiceFactory
{
    /// <inheritdoc />
    public IHashService CreateMd5HashService(int bufferSize = 4096)
        => new HashService(() => new MD5Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha1HashService(int bufferSize = 4096)
        => new HashService(() => new Sha1Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha3HashService(int bitLength = 512, int bufferSize = 4096)
        => new HashService(() => new Sha3Digest(bitLength), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha256HashService(int bufferSize = 4096)
        => new HashService(() => new Sha256Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha512HashService(int bufferSize = 4096)
        => new HashService(() => new Sha512Digest(), bufferSize);
}