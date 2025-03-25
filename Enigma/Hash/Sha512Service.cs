using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;

namespace Enigma.Hash;

/// <summary>
/// SHA512 hash service
/// </summary>
public class Sha512Service : HashServiceBase
{
    /// <inheritdoc />
    public override int HashSize => 64;

    /// <inheritdoc />
    protected override IDigest BuildDigest()
        => new Sha512Digest();
}