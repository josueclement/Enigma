using Org.BouncyCastle.Crypto.Paddings;
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
    /// <param name="paddingFactory">Padding factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize);
    
    /// <summary>
    /// Create a block cipher service with Cipher-Block-Chaining (CBC) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="paddingFactory">Padding factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize);
    
    /// <summary>
    /// Create a block cipher service with Segmented Integer Counter (SIC) mode
    /// </summary>
    /// <param name="engineFactory">Engine factory</param>
    /// <param name="paddingFactory">Padding factory</param>
    /// <param name="bufferSize">Buffer size</param>
    IBlockCipherService CreateSicService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize);
}