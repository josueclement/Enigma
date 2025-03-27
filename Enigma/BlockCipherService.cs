using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma;

/// <summary>
/// Block cipher service
/// </summary>
public class BlockCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;

    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <summary>
    /// Constructor for <see cref="BlockCipherService"/>
    /// </summary>
    public BlockCipherService(Func<IBufferedCipher> cipherFactory)
    {
        _cipherFactory = cipherFactory;
    }
    
    /// <summary>
    /// Asynchronously encrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    /// <param name="padding">Padding</param>
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IPaddingService padding)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        
        var padDone = false;
        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];
        var enc = new byte[BUFFER_SIZE];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);

            if (bytesRead == BUFFER_SIZE)
            {
                cipher.ProcessBytes(buffer, enc, 0);
                await output.WriteAsync(enc, 0, bytesRead).ConfigureAwait(false);
            }
            else if (bytesRead > 0)
            {
                var smallBuffer = new byte[bytesRead];
                Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                var padData = padding.Pad(smallBuffer, cipher.GetBlockSize());
                cipher.ProcessBytes(padData, enc, 0);
                await output.WriteAsync(enc, 0, padData.Length).ConfigureAwait(false);
                padDone = true;
            }

            // if (notifyProgression != null && bytesRead > 0)
            //     notifyProgression(bytesRead);
        } while (bytesRead == BUFFER_SIZE);

        if (!padDone)
        {
            buffer = [];
            var padData = padding.Pad(buffer, cipher.GetBlockSize());
            cipher.ProcessBytes(padData, enc, 0);
            await output.WriteAsync(enc, 0, padData.Length).ConfigureAwait(false);
        } 
    }

    /// <summary>
    /// Asynchronously decrypt
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <param name="output">Output stream</param>
    /// <param name="cipherParameters">Cipher parameters</param>
    /// <param name="padding">Padding</param>
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        ICipherParameters cipherParameters,
        IPaddingService padding)
    {
        var cipher = _cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        
        byte[]? backup = null;
        int bytesRead;
        var buffer = new byte[BUFFER_SIZE];
        var dec = new byte[BUFFER_SIZE];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, BUFFER_SIZE).ConfigureAwait(false);

            if (bytesRead > 0)
            {
                if (backup != null)
                {
                    await output.WriteAsync(backup, 0, backup.Length).ConfigureAwait(false);
                    backup = null;
                }

                if (bytesRead == BUFFER_SIZE)
                {
                    cipher.ProcessBytes(buffer, dec, 0);
                    backup = new byte[bytesRead];
                    Array.Copy(dec, 0, backup, 0, bytesRead);
                }
                else
                {
                    dec = new byte[bytesRead];
                    var smallBuffer = new byte[bytesRead];
                    Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                    cipher.ProcessBytes(smallBuffer, dec, 0);
                    var unpadData = padding.Unpad(dec, cipher.GetBlockSize());
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }

                // notifyProgression?.Invoke(bytesRead);
            }
            else
            {
                if (backup != null)
                {
                    var unpadData = padding.Unpad(backup, cipher.GetBlockSize());
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }
            }
        } while (bytesRead == BUFFER_SIZE); 
    }
}