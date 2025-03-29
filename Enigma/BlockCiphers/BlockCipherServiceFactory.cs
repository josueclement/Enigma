using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service factory
/// </summary>
// TODO: Add padding parameter nullable and when null no padding like now
public class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new EcbBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new CbcBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSicService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new SicBlockCipher(engineFactory())), bufferSize);
}