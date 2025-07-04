using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Cryptography.Padding;

/// <summary>
/// Factory that creates various padding service implementations used for cryptographic operations.
/// This factory provides methods to create different standard padding algorithms including:
/// No Padding, PKCS7, ISO-7816, ISO-10126, and X.923.
/// </summary>
/// <remarks>
/// The factory implements the IPaddingServiceFactory interface and instantiates
/// specific padding service implementations based on the requested padding algorithm.
/// Each method returns an IPaddingService that encapsulates the corresponding BouncyCastle padding implementation.
/// </remarks>
public class PaddingServiceFactory : IPaddingServiceFactory
{
    /// <inheritdoc />
    public IPaddingService CreateNoPaddingService()
        => new NoPaddingService();

    /// <inheritdoc />
    public IPaddingService CreatePkcs7Service()
        => new PaddingService(() => new Pkcs7Padding());

    /// <inheritdoc />
    public IPaddingService CreateIso7816Service()
        => new PaddingService(() => new ISO7816d4Padding());

    /// <inheritdoc />
    public IPaddingService CreateIso10126Service()
        => new PaddingService(() => new ISO10126d2Padding());

    /// <inheritdoc />
    public IPaddingService CreateX923Service()
        => new PaddingService(() => new X923Padding());
}