using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto;

namespace Enigma.Hash;

/// <summary>
/// MD5 hash service
/// </summary>
public class Md5Service : HashServiceBase
{
    /// <inheritdoc />
    public override int HashSize => 16;

    /// <inheritdoc />
    protected override IDigest BuildDigest()
        => new MD5Digest();
}