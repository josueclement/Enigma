using Enigma.Utils;
using Org.BouncyCastle.Crypto;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.StreamCiphers;

/// <summary>
/// Stream cipher service base class
/// </summary>
public abstract class StreamCipherServiceBase : IStreamCipherService
{
    // ReSharper disable once InconsistentNaming
    private const int BUFFER_SIZE = 4096;
    
    /// <summary>
    /// Gets key size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int KeySize { get; }
    
    /// <summary>
    /// Gets nonce size
    /// </summary>
    // ReSharper disable once MemberCanBeProtected.Global
    public abstract int NonceSize { get; }
    
    /// <summary>
    /// Abstract cipher factory method
    /// </summary>
    /// <param name="forEncryption">True for encryption, False for decryption</param>
    /// <param name="key">Key</param>
    /// <param name="nonce">Nonce</param>
    /// <returns>Cipher</returns>
    protected abstract IStreamCipher BuildCipher(bool forEncryption, byte[] key, byte[] nonce);
    
    /// <inheritdoc />
    public void GenerateKeyNonce(out byte[] key, out byte[] nonce)
    {
        key = RandomUtils.GenerateRandomBytes(KeySize);
        nonce = RandomUtils.GenerateRandomBytes(NonceSize);
    }

    /// <inheritdoc />
    public async Task EncryptAsync(Stream input, Stream output, byte[] key, byte[] nonce)
    {
        var cipher = BuildCipher(true, key, nonce);
        
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
        var cipher = BuildCipher(false, key, nonce);
        
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