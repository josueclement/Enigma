using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.Hash;

/// <summary>
/// SHA256 hash service
/// </summary>
public class Sha256Service : HashServiceBase
{
    /// <inheritdoc />
    public override int HashSize => 32;

    /// <inheritdoc />
    protected override IDigest BuildDigest()
        => new Sha256Digest();
}