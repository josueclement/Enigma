using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Extensions;

/// <summary>
/// BlockCipherService CBC extensions
/// </summary>
public static class BlockCipherServiceCbcExtensions
{
    /// <summary>
    /// Asynchronously encrypt with cipher in CBC mode
    /// </summary>
    /// <param name="service">Block cipher service</param>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="engine">Block cipher engine</param>
    /// <param name="key">Key</param>
    /// <param name="iv">Iv</param>
    /// <param name="padding">Padding</param>
    public static async Task EncryptCbcAsync(
        this BlockCipherService service,
        Stream input, Stream output,
        IBlockCipher engine,
        byte[] key, byte[] iv,
        IPaddingService padding)
        => await ProcessCbcAsync(service, input, output, engine, true, key, iv, padding).ConfigureAwait(false);
    
    /// <summary>
    /// Asynchronously decrypt with cipher in CBC mode
    /// </summary>
    /// <param name="service">Block cipher service</param>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="engine">Block cipher engine</param>
    /// <param name="key">Key</param>
    /// <param name="iv">Iv</param>
    /// <param name="padding">Padding</param>
    public static async Task DecryptCbcAsync(
        this BlockCipherService service,
        Stream input, Stream output,
        IBlockCipher engine,
        byte[] key, byte[] iv,
        IPaddingService padding)
        => await ProcessCbcAsync(service, input, output, engine, false, key, iv, padding).ConfigureAwait(false);
    
    private static async Task ProcessCbcAsync(
        BlockCipherService service,
        Stream input, Stream output,
        IBlockCipher engine,
        bool forEncryption,
        byte[] key, byte[] iv,
        IPaddingService padding)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(engine));
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.Init(forEncryption, parameters);
        await service.EncryptAsync(input, output, cipher, padding).ConfigureAwait(false);
    }
}