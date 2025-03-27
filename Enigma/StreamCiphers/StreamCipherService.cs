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
public class StreamCipherService(Func<IStreamCipher> cipherFactory) : IStreamCipherService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(true, parameters);
        
        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];
        var enc = new byte[BUFFER_SIZE];
        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);
            if (bytesRead > 0)
            {
                cipher.ProcessBytes(buffer, 0, bytesRead, enc, 0);
                await output.WriteAsync(enc, 0, bytesRead).ConfigureAwait(false);

                // notifyProgression?.Invoke(bytesRead);
            }

        } while (bytesRead == BUFFER_SIZE);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(false, parameters);
        
        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];
        var dec = new byte[BUFFER_SIZE];
        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);
            if (bytesRead > 0)
            {
                cipher.ProcessBytes(buffer, 0, bytesRead, dec, 0);
                await output.WriteAsync(dec, 0, bytesRead).ConfigureAwait(false);

                // notifyProgression?.Invoke(bytesRead);
            }

        } while (bytesRead == BUFFER_SIZE);
    }
}