using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.BlockCiphers;

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

/// <summary>
/// Block cipher service factory
/// </summary>
public class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateEcbBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new EcbBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCbcBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new CbcBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSicBlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new SicBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCfbBlockCipherService(Func<IBlockCipher> engineFactory, int bitBlockSize = 128, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new CfbBlockCipher(engineFactory(), bitBlockSize)), bufferSize);
}