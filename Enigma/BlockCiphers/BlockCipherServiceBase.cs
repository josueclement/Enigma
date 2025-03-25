using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Block cipher service base class
/// </summary>
public abstract class BlockCipherServiceBase : IBlockCipherService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <summary>
    /// Gets key size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int KeySize { get; }
    
    /// <summary>
    /// Gets IV size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int IvSize { get; }
    
    /// <summary>
    /// Gets block size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int BlockSize { get; }
    
    /// <summary>
    /// Abstract cipher factory method
    /// </summary>
    /// <param name="forEncryption">True for encryption, False for decryption</param>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    /// <returns>Cipher</returns>
    protected abstract IBufferedCipher BuildCipher(bool forEncryption, byte[] key, byte[] iv);

    /// <summary>
    /// Generate random key and IV
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">IV</param>
    public void GenerateKeyIv(out byte[] key, out byte[] iv)
    {
        key = RandomUtils.GenerateRandomBytes(KeySize);
        iv = RandomUtils.GenerateRandomBytes(IvSize);
    }

    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding)
    {
        var cipher = BuildCipher(true, key, iv);
        await EncryptStreamAsync(input, output, cipher, padding).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task DecryptAsync(Stream input, Stream output, byte[] key, byte[] iv, IPaddingService padding)
    {
        var cipher = BuildCipher(false, key, iv);
        await DecryptStreamAsync(input, output, cipher, padding).ConfigureAwait(false);
    }

    private async Task EncryptStreamAsync(
        Stream input,
        Stream output,
        IBufferedCipher cipher,
        IPaddingService padding)
    {
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
                var padData = padding.Pad(smallBuffer, BlockSize);
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
            var padData = padding.Pad(buffer, BlockSize);
            cipher.ProcessBytes(padData, enc, 0);
            await output.WriteAsync(enc, 0, padData.Length).ConfigureAwait(false);
        } 
    }

    private async Task DecryptStreamAsync(
        Stream input,
        Stream output,
        IBufferedCipher cipher,
        IPaddingService padding)
    {
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
                    var unpadData = padding.Unpad(dec, BlockSize);
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }

                // notifyProgression?.Invoke(bytesRead);
            }
            else
            {
                if (backup != null)
                {
                    var unpadData = padding.Unpad(backup, BlockSize);
                    await output.WriteAsync(unpadData, 0, unpadData.Length).ConfigureAwait(false);
                }
            }
        } while (bytesRead == BUFFER_SIZE); 
    }
}