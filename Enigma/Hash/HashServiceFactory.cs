using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.Hash;

/// <summary>
/// Factory for creating various cryptographic hash service implementations.
/// </summary>
/// <remarks>
/// This factory provides methods to create different hash services including MD5, SHA-1, 
/// SHA-3, SHA-256, and SHA-512, each with configurable buffer sizes for optimizing performance.
/// All hash implementations are based on the BouncyCastle cryptography library.
/// </remarks>
public class HashServiceFactory : IHashServiceFactory
{
    /// <inheritdoc />
    public IHashService CreateMd5Service(int bufferSize = 4096)
        => new HashService(() => new MD5Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha1Service(int bufferSize = 4096)
        => new HashService(() => new Sha1Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha3Service(int bitLength = 512, int bufferSize = 4096)
        => new HashService(() => new Sha3Digest(bitLength), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha256Service(int bufferSize = 4096)
        => new HashService(() => new Sha256Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha512Service(int bufferSize = 4096)
        => new HashService(() => new Sha512Digest(), bufferSize);
}