using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service
/// </summary>
/// <param name="cipherFactory">Cipher factory</param>
/// <param name="bufferSize">Buffer size</param>
public class BlockCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = 4096) : IBlockCipherService
{
    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, IPaddingService padding)
    {
        var cipher = cipherFactory();
        cipher.Init(forEncryption: true, cipherParameters);
        
        var padDone = false;
        int bytesRead;
        var buffer = new byte[bufferSize];
        var enc = new byte[bufferSize];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);

            if (bytesRead == bufferSize)
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
        } while (bytesRead == bufferSize);

        if (!padDone)
        {
            buffer = [];
            var padData = padding.Pad(buffer, cipher.GetBlockSize());
            cipher.ProcessBytes(padData, enc, 0);
            await output.WriteAsync(enc, 0, padData.Length).ConfigureAwait(false);
        } 
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, ICipherParameters cipherParameters, IPaddingService padding)
    {
        var cipher = cipherFactory();
        cipher.Init(forEncryption: false, cipherParameters);
        
        byte[]? backup = null;
        int bytesRead;
        var buffer = new byte[bufferSize];
        var dec = new byte[bufferSize];

        do
        {
            bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);

            if (bytesRead > 0)
            {
                if (backup is not null)
                {
                    await output.WriteAsync(backup, 0, backup.Length).ConfigureAwait(false);
                    backup = null;
                }

                if (bytesRead == bufferSize)
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
            }
            else
            {
                if (backup is not null)
                {
                    var unpadData = padding.Unpad(backup, cipher.GetBlockSize());
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }
            }
        } while (bytesRead == bufferSize); 
    }
}