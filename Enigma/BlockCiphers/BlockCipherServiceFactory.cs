using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service factory
/// </summary>
public class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding>? paddingFactory = null, int bufferSize = 4096)
    {
        return paddingFactory is null ?
            new BlockCipherService(() => new BufferedBlockCipher(new EcbBlockCipher(engineFactory())), bufferSize) :
            new BlockCipherService(() => new PaddedBufferedBlockCipher(new EcbBlockCipher(engineFactory()), paddingFactory()), bufferSize);
    }

    /// <inheritdoc />
    public IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding>? paddingFactory = null, int bufferSize = 4096)
    {
        return paddingFactory is null ?
            new BlockCipherService(() => new BufferedBlockCipher(new CbcBlockCipher(engineFactory())), bufferSize) :
            new BlockCipherService(() => new PaddedBufferedBlockCipher(new CbcBlockCipher(engineFactory()), paddingFactory()), bufferSize);
    }

    /// <inheritdoc />
    public IBlockCipherService CreateSicService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding>? paddingFactory = null, int bufferSize = 4096)
    {
        return paddingFactory is null ?
            new BlockCipherService(() => new BufferedBlockCipher(new SicBlockCipher(engineFactory())), bufferSize) :
            new BlockCipherService(() => new PaddedBufferedBlockCipher(new SicBlockCipher(engineFactory()), paddingFactory()), bufferSize);
    }
}