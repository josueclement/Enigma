using Org.BouncyCastle.Crypto;

namespace Enigma;

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
}