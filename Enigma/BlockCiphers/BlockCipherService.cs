using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service
/// </summary>
public class BlockCipherService : IBlockCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="cipherFactory">Cipher factory</param>
    /// <param name="bufferSize">Buffer size</param>
    public BlockCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096)
    {
        _cipherFactory = cipherFactory;
        _bufferSize = bufferSize;
    }

    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    /// <param name="algorithmName"></param>
    /// <param name="bufferSize"></param>
    public BlockCipherService(string algorithmName, int bufferSize = 4096)
        : this(() => CipherUtilities.GetCipher(algorithmName), bufferSize) { }
    
    /// <inheritdoc />
    public (int keySizeInBytes, int ivSizeInBytes) GetKeyIvSize()
    {
        var cipher = _cipherFactory();
        var engineName = cipher.AlgorithmName.Split('/').FirstOrDefault();

        if (engineName is null)
            throw new InvalidOperationException("Algorithm name not found");

        return engineName switch
        {
            "AES" => (32, 16),
            "Serpent" => (32, 16),
            "Camellia" => (32, 16),
            "Twofish" => (32, 16),
            "Blowfish" => (56, 16),
            "DESede" => (24, 8),
            "DES" => (8, 8),
            _ => throw new NotImplementedException($"GetKeyIvSize not implemented for {engineName}")
        };
    }
    
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        await ProcessStreamsAsync(input, output, cipher).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        await ProcessStreamsAsync(input, output, cipher).ConfigureAwait(false);
    }

    private async Task ProcessStreamsAsync(Stream input, Stream output, IBufferedCipher cipher)
    {
        var buffer = new byte[_bufferSize];
        byte[] outputBuffer;
        int bytesRead;
    
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            outputBuffer = cipher.ProcessBytes(buffer, 0, bytesRead);
            if (outputBuffer is { Length: > 0 })
                await output.WriteAsync(outputBuffer, 0, outputBuffer.Length).ConfigureAwait(false);
        }
    
        outputBuffer = cipher.DoFinal();
        if (outputBuffer is { Length: > 0 })
            await output.WriteAsync(outputBuffer, 0, outputBuffer.Length).ConfigureAwait(false); 
    }
}