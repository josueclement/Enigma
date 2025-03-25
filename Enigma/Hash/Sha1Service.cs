using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;

namespace Enigma.Hash;

/// <summary>
/// SHA1 hash service
/// </summary>
public class Sha1Service : HashServiceBase
{
    /// <inheritdoc />
    public override int HashSize => 20;

    /// <inheritdoc />
    protected override IDigest BuildDigest()
        => new Sha1Digest();
}