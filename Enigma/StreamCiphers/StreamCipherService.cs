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
public class StreamCipherService(Func<IStreamCipher> cipherFactory, int bufferSize = 4096) : IStreamCipherService
{
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);
        
        int bytesRead;
        var buffer = new byte[bufferSize];
        var enc = new byte[bufferSize];
        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
            if (bytesRead > 0)
            {
                cipher.ProcessBytes(buffer, 0, bytesRead, enc, 0);
                await output.WriteAsync(enc, 0, bytesRead).ConfigureAwait(false);
            }

        } while (bytesRead == bufferSize);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);
        
        int bytesRead;
        var buffer = new byte[bufferSize];
        var dec = new byte[bufferSize];
        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
            if (bytesRead > 0)
            {
                cipher.ProcessBytes(buffer, 0, bytesRead, dec, 0);
                await output.WriteAsync(dec, 0, bytesRead).ConfigureAwait(false);
            }

        } while (bytesRead == bufferSize);
    }
}