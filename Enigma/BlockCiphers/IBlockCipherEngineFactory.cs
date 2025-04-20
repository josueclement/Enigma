using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Factory interface for creating various block cipher engine implementations.
/// </summary>
public interface IBlockCipherEngineFactory
{
    /// <summary>
    /// Creates a new instance of an AES block cipher engine
    /// </summary>
    IBlockCipher CreateAesEngine();

    /// <summary>
    /// Creates a new instance of a Serpent block cipher engine
    /// </summary>
    IBlockCipher CreateSerpentEngine();

    /// <summary>
    /// Creates a new instance of a Camellia block cipher engine
    /// </summary>
    IBlockCipher CreateCamelliaEngine();

    /// <summary>
    /// Creates a new instance of a Twofish block cipher engine
    /// </summary>
    IBlockCipher CreateTwofishEngine();
    
    /// <summary>
    /// Creates a new instance of a Blowfish block cipher engine
    /// </summary>
    IBlockCipher CreateBlowfishEngine();
    
    /// <summary>
    /// Creates a new instance of a DES block cipher engine
    /// </summary>
    IBlockCipher CreateDesEngine();
    
    /// <summary>
    /// Creates a new instance of a TripleDES block cipher engine
    /// </summary>
    IBlockCipher CreateTripleDesEngine();
    
    /// <summary>
    /// Creates a new instance of a Cast-128 (CAST5) block cipher engine
    /// </summary>
    IBlockCipher CreateCast5Engine();
    
    /// <summary>
    /// Creates a new instance of an IDEA block cipher engine
    /// </summary>
    IBlockCipher CreateIdeaEngine();
    
    /// <summary>
    /// Creates a new instance of a SEED block cipher engine
    /// </summary>
    IBlockCipher CreateSeedEngine();
    
    /// <summary>
    /// Creates a new instance of an ARIA block cipher engine
    /// </summary>
    IBlockCipher CreateAriaEngine();
    
    /// <summary>
    /// Creates a new instance of a SM4 block cipher engine
    /// </summary>
    IBlockCipher CreateSm4Engine();
}