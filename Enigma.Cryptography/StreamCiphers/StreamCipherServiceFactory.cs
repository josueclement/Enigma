using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;

namespace Enigma.Cryptography.StreamCiphers;

/// <summary>
/// A factory for creating stream cipher services.
/// </summary>
public class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha7539Service(int bufferSize = 4096)
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaCha7539Engine()), bufferSize);

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Service(int bufferSize = 4096)
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaChaEngine()), bufferSize);

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20Service(int bufferSize = 4096)
        => new StreamCipherService(() => new BufferedStreamCipher(new Salsa20Engine()), bufferSize);
}