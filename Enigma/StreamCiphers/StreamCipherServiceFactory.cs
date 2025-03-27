using Org.BouncyCastle.Crypto.Engines;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service factory
/// </summary>
public class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Rfc7539StreamCipherService()
        => new StreamCipherService(() => new ChaCha7539Engine());

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20StreamCipherService()
        => new StreamCipherService(() => new ChaChaEngine());

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20StreamCipherService()
        => new StreamCipherService(() => new Salsa20Engine());
}