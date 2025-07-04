using Org.BouncyCastle.Crypto;

namespace Enigma.Cryptography.BlockCiphers;

/// <summary>
/// Factory interface for creating various block cipher parameter configurations.
/// This interface provides methods to create parameters for different cipher modes
/// like ECB, CBC, SIC (CTR), and GCM with appropriate initialization values.
/// </summary>
public interface IBlockCipherParametersFactory
{
    /// <summary>
    /// Creates parameters for Electronic Codebook (ECB) mode.
    /// ECB is the simplest encryption mode that encrypts each block independently,
    /// making it less secure for data with recognizable patterns.
    /// </summary>
    /// <param name="key">The secret key used for encryption/decryption. Length depends on the underlying cipher.</param>
    /// <returns>Cipher parameters configured for ECB mode operation.</returns>
    ICipherParameters CreateEcbParameters(byte[] key);
    
    /// <summary>
    /// Creates parameters for Cipher Block Chaining (CBC) mode.
    /// CBC enhances security by XORing each plaintext block with the previous ciphertext block,
    /// requiring an initialization vector (IV) for the first block.
    /// </summary>
    /// <param name="key">The secret key used for encryption/decryption. Length depends on the underlying cipher.</param>
    /// <param name="iv">Initialization vector that must be random and unpredictable. Usually the same length as the block size.</param>
    /// <returns>Cipher parameters configured for CBC mode operation.</returns>
    ICipherParameters CreateCbcParameters(byte[] key, byte[] iv);
    
    /// <summary>
    /// Creates parameters for Segmented Integer Counter (SIC) mode, also known as CTR mode.
    /// SIC/CTR turns a block cipher into a stream cipher by encrypting sequential counter values,
    /// then XORing the result with the plaintext.
    /// </summary>
    /// <param name="key">The secret key used for encryption/decryption. Length depends on the underlying cipher.</param>
    /// <param name="nonce">Number used once that serves as the initial counter value. Should be unique for each encryption with the same key.</param>
    /// <returns>Cipher parameters configured for SIC/CTR mode operation.</returns>
    ICipherParameters CreateSicParameters(byte[] key, byte[] nonce);
    
    /// <summary>
    /// Creates parameters for Galois/Counter Mode (GCM).
    /// GCM provides both authenticated encryption and data integrity, combining
    /// counter mode encryption with Galois field multiplication for authentication.
    /// </summary>
    /// <param name="key">The secret key used for encryption/decryption. Length depends on the underlying cipher.</param>
    /// <param name="nonce">Number used once that must be unique for each encryption with the same key. Typically 12 bytes.</param>
    /// <param name="macSize">Message Authentication Code size in bits, determining the strength of authentication. Default is 128 bits.</param>
    /// <returns>Cipher parameters configured for GCM mode operation without associated data.</returns>
    ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, int macSize = 128);
    
    /// <summary>
    /// Creates parameters for Galois/Counter Mode (GCM) with additional authenticated data.
    /// This mode provides authenticated encryption that allows for data (associated text)
    /// to be authenticated but not encrypted along with the message content.
    /// </summary>
    /// <param name="key">The secret key used for encryption/decryption. Length depends on the underlying cipher.</param>
    /// <param name="nonce">Number used once that must be unique for each encryption with the same key. Typically 12 bytes.</param>
    /// <param name="associatedText">Additional data that will be authenticated but not encrypted.</param>
    /// <param name="macSize">Message Authentication Code size in bits, determining the strength of authentication. Default is 128 bits.</param>
    /// <returns>Cipher parameters configured for GCM mode operation with associated data for additional authentication.</returns>
    ICipherParameters CreateGcmParameters(byte[] key, byte[] nonce, byte[] associatedText, int macSize = 128);
}