﻿using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma;

/// <summary>
/// Stream cipher service
/// </summary>
public class StreamCipherService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <summary>
    /// Asynchronously encrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipher">Cipher</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    public async Task EncryptAsync(Stream input, Stream output, IStreamCipher cipher, byte[] key, byte[] nonce)
    {
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

    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipher">Cipher</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    public async Task DecryptAsync(Stream input, Stream output, IStreamCipher cipher, byte[] key, byte[] nonce)
    {
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