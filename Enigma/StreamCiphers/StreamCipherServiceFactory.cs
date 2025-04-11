using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service factory
/// </summary>
public class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha7539Service()
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaCha7539Engine()));

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Service()
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaChaEngine()));

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20Service()
        => new StreamCipherService(() => new BufferedStreamCipher(new Salsa20Engine()));
}