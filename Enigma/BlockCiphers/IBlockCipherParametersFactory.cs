using Org.BouncyCastle.Crypto;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher parameters factory
/// </summary>
public interface IBlockCipherParametersFactory
{
    /// <summary>
    /// Create ECB parameters
    /// </summary>
    /// <param name="key">Key</param>
    ICipherParameters CreateEcbParameters(byte[] key);
    
    /// <summary>
    /// Create CBC parameters
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    ICipherParameters CreateCbcParameters(byte[] key, byte[] iv);
    
    /// <summary>
    /// Create SIC parameters
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    ICipherParameters CreateSicParameters(byte[] key, byte[] nonce);
    
    /// <summary>
    /// Create GCM parameters
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    /// <param name="macSize">MAC size in bits</param>
    ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, int macSize = 128);
    
    /// <summary>
    /// Create GCM parameters
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    /// <param name="associatedText">Associated text</param>
    /// <param name="macSize">MAC size in bits</param>
    ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, byte[] associatedText, int macSize = 128);
}