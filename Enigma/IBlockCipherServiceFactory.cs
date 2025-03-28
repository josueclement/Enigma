using Org.BouncyCastle.Crypto;
using System;

namespace Enigma;

/// <summary>
/// Definition for block cipher service factory
/// </summary>
public interface IBlockCipherServiceFactory
{
    /// <summary>
    /// Create a block cipher service with Electronic Code Book (ECB) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateEcbBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize);
    
    /// <summary>
    /// Create a block cipher service with Cipher-Block-Chaining (CBC) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateCbcBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize);
    
    /// <summary>
    /// Create a block cipher service with Segmented Integer Counter (SIC) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateSicBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize);
    
    /// <summary>
    /// Create a block cipher service with Cipher-FeedBack (CFB) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="bitBlockSize">Bit block size</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateCfbBlockCipherService(Func<IBlockCipher> engineFactory, int bitBlockSize, int bufferSize);
}