using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher engine factory
/// </summary>
public class BlockCipherEngineFactory : IBlockCipherEngineFactory
{
    /// <inheritdoc />
    public IBlockCipher CreateAesEngine()
        => new AesEngine();
    
    /// <inheritdoc />
    public IBlockCipher CreateSerpentEngine()
        => new SerpentEngine();
    
    /// <inheritdoc />
    public IBlockCipher CreateCamelliaEngine()
        => new CamelliaEngine();
    
    /// <inheritdoc />
    public IBlockCipher CreateTwofishEngine()
        => new TwofishEngine();

    /// <inheritdoc />
    public IBlockCipher CreateBlowfishEngine()
        => new BlowfishEngine();

    /// <inheritdoc />
    public IBlockCipher CreateDesEngine()
        => new DesEngine();

    /// <inheritdoc />
    public IBlockCipher CreateTripleDesEngine()
        => new DesEdeEngine();
}