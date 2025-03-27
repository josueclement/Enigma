using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher service factory
/// </summary>
public interface IBlockCipherServiceFactory
{
    /// <summary>
    /// Create ECB block cipher service
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    IBlockCipherService CreateEcbBlockCipherService(Func<IBlockCipher> cipherFactory);
    
    /// <summary>
    /// Create CBC block cipher service
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    IBlockCipherService CreateCbcBlockCipherService(Func<IBlockCipher> cipherFactory);
    
    /// <summary>
    /// Create CTR block cipher service
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    IBlockCipherService CreateCtrBlockCipherService(Func<IBlockCipher> cipherFactory);
    
    /// <summary>
    /// Create a block cipher service with CFB mode
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bitBlockSize">Bit block size</param>
    IBlockCipherService CreateCfbBlockCipherService(Func<IBlockCipher> cipherFactory, int bitBlockSize);
}

/// <summary>
/// Block cipher service factory
/// </summary>
public class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateEcbBlockCipherService(Func<IBlockCipher> cipherFactory)
        => new BlockCipherService(() => new BufferedBlockCipher(new EcbBlockCipher(cipherFactory())));

    /// <inheritdoc />
    public IBlockCipherService CreateCbcBlockCipherService(Func<IBlockCipher> cipherFactory)
        => new BlockCipherService(() => new BufferedBlockCipher(new CbcBlockCipher(cipherFactory())));

    /// <inheritdoc />
    public IBlockCipherService CreateCtrBlockCipherService(Func<IBlockCipher> cipherFactory)
        => new BlockCipherService(() => new BufferedBlockCipher(new SicBlockCipher(cipherFactory())));

    /// <inheritdoc />
    public IBlockCipherService CreateCfbBlockCipherService(Func<IBlockCipher> cipherFactory, int bitBlockSize = 128)
        => new BlockCipherService(() => new BufferedBlockCipher(new CfbBlockCipher(cipherFactory(), bitBlockSize)));
}