using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;

namespace Enigma.Hash;

/// <summary>
/// SHA3 hash service
/// </summary>
public class Sha3Service : HashServiceBase
{
    /// <inheritdoc />
    public override int HashSize => 64;

    /// <inheritdoc />
    protected override IDigest BuildDigest()
        => new Sha3Digest(512);
}