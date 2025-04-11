using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service
/// </summary>
/// <param name="cipherFactory">Cipher factory</param>
/// <param name="bufferSize">Buffer size</param>
public class StreamCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096) : IStreamCipherService
{
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);
        await EncryptStreamAsync(input, output, cipher).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);
        await DecryptStreamAsync(input, output, cipher).ConfigureAwait(false);
    }
    
    private async Task EncryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher)
    {
        using var cipherStream = new CipherStream(output, null, cipher);
        var buffer = new byte[bufferSize];
        int bytesRead;
        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            await cipherStream.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
        }
    }

    private async Task DecryptStreamAsync(Stream input, Stream output, IBufferedCipher cipher)
    {
        using var cipherStream = new CipherStream(input, cipher, null);
        var buffer = new byte[bufferSize];
        int bytesRead;
        while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
        {
            await output.WriteAsync(buffer, 0, bytesRead).ConfigureAwait(false);
        } 
    }
}