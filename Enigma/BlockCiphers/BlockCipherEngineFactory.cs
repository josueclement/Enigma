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

    /// <inheritdoc />
    public IBlockCipher CreateCast5Engine()
        => new Cast5Engine();

    /// <inheritdoc />
    public IBlockCipher CreateIdeaEngine()
        => new IdeaEngine();

    /// <inheritdoc />
    public IBlockCipher CreateSeedEngine()
        => new SeedEngine();

    /// <inheritdoc />
    public IBlockCipher CreateAriaEngine()
        => new AriaEngine();

    /// <inheritdoc />
    public IBlockCipher CreateSm4Engine()
        => new SM4Engine();
}