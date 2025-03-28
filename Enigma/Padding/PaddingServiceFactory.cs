using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Padding;

/// <summary>
/// Padding service factory
/// </summary>
public class PaddingServiceFactory : IPaddingServiceFactory
{
    /// <inheritdoc />
    public IPaddingService CreateNoPaddingService()
        => new NoPaddingService();

    /// <inheritdoc />
    public IPaddingService CreatePkcs7PaddingService()
        => new PaddingService(() => new Pkcs7Padding());

    /// <inheritdoc />
    public IPaddingService CreateIso7816PaddingService()
        => new PaddingService(() => new ISO7816d4Padding());

    /// <inheritdoc />
    public IPaddingService CreateIso10126PaddingService()
        => new PaddingService(() => new ISO10126d2Padding());

    /// <inheritdoc />
    public IPaddingService CreateX923PaddingService()
        => new PaddingService(() => new X923Padding());
}