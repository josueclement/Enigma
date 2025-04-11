using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher engine factory
/// </summary>
public interface IBlockCipherEngineFactory
{
    /// <summary>
    /// Create AES block cipher engine
    /// </summary>
    IBlockCipher CreateAesEngine();

    /// <summary>
    /// Create Serpent block cipher engine
    /// </summary>
    IBlockCipher CreateSerpentEngine();

    /// <summary>
    /// Create Camellia block cipher engine
    /// </summary>
    IBlockCipher CreateCamelliaEngine();

    /// <summary>
    /// Create Twofish block cipher engine
    /// </summary>
    IBlockCipher CreateTwofishEngine();
    
    /// <summary>
    /// Create Blowfish block cipher engine
    /// </summary>
    IBlockCipher CreateBlowfishEngine();
    
    /// <summary>
    /// Create DES block cipher engine
    /// </summary>
    IBlockCipher CreateDesEngine();
    
    /// <summary>
    /// Create TripleDES block cipher engine
    /// </summary>
    IBlockCipher CreateTripleDesEngine();
    
    /// <summary>
    /// Create Cast-128 (CAST5) block cipher engine
    /// </summary>
    IBlockCipher CreateCast5Engine();
    
    /// <summary>
    /// Create IDEA block cipher engine
    /// </summary>
    IBlockCipher CreateIdeaEngine();
    
    /// <summary>
    /// Create SEED block cipher engine
    /// </summary>
    IBlockCipher CreateSeedEngine();
    
    /// <summary>
    /// Create ARIA block cipher engine
    /// </summary>
    IBlockCipher CreateAriaEngine();
    
    /// <summary>
    /// Create SM4 block cipher engine
    /// </summary>
    IBlockCipher CreateSm4Engine();
}