using Org.BouncyCastle.Crypto.Engines;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service factory
/// </summary>
public class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha7539Service()
        => new StreamCipherService(() => new ChaCha7539Engine());

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Service()
        => new StreamCipherService(() => new ChaChaEngine());

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20Service()
        => new StreamCipherService(() => new Salsa20Engine());
}