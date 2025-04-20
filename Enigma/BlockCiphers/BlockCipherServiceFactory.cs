using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// A factory for creating block cipher services with various modes of operation and padding schemes.
/// </summary>
/// <remarks>
/// <para>
/// This factory provides methods to create block cipher services using different cipher modes:
/// <list type="bullet">
///   <item><description>ECB (Electronic Codebook)</description></item>
///   <item><description>CBC (Cipher Block Chaining)</description></item>
///   <item><description>SIC (Segmented Integer Counter, also known as CTR mode)</description></item>
///   <item><description>GCM (Galois/Counter Mode)</description></item>
/// </list>
/// </para>
/// </remarks>
public class BlockCipherServiceFactory : IBlockCipherServiceFactory
{
    /// <inheritdoc />
    public IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new EcbBlockCipher(engineFactory())), bufferSize);
    
    /// <inheritdoc />
    public IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new PaddedBufferedBlockCipher(new EcbBlockCipher(engineFactory()), paddingFactory()), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new CbcBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new PaddedBufferedBlockCipher(new CbcBlockCipher(engineFactory()), paddingFactory()), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateSicService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedBlockCipher(new SicBlockCipher(engineFactory())), bufferSize);

    /// <inheritdoc />
    public IBlockCipherService CreateGcmService(Func<IBlockCipher> engineFactory, int bufferSize = 4096)
        => new BlockCipherService(() => new BufferedAeadBlockCipher(new GcmBlockCipher(engineFactory())), bufferSize);
}