using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto;
using System;

namespace Enigma.BlockCiphers;

/// <summary>
/// Factory interface for creating block cipher encryption/decryption services with various operation modes.
/// This factory abstracts the complexities of setting up different block cipher modes and padding schemes.
/// </summary>
/// <remarks>
/// Block ciphers encrypt fixed-size blocks of data (typically 64 or 128 bits).
/// Different operation modes (ECB, CBC, SIC, GCM) determine how these blocks are processed
/// and how the encryption of one block relates to another.
/// </remarks>
public interface IBlockCipherServiceFactory
{
    /// <summary>
    /// Creates a block cipher service operating in Electronic Code Book (ECB) mode.
    /// </summary>
    /// <remarks>
    /// ECB mode encrypts each block independently using the same key.
    /// Note: ECB is generally not recommended for encrypting large amounts of data
    /// as identical plaintext blocks will encrypt to identical ciphertext blocks.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a block cipher service operating in Electronic Code Book (ECB) mode with custom padding.
    /// </summary>
    /// <remarks>
    /// ECB mode encrypts each block independently using the same key.
    /// This overload allows specifying a custom padding scheme for handling data that isn't aligned to block boundaries.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="paddingFactory">Factory function that creates the padding mechanism to use for incomplete blocks.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateEcbService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a block cipher service operating in Cipher-Block-Chaining (CBC) mode.
    /// </summary>
    /// <remarks>
    /// In CBC mode, each plaintext block is XORed with the previous ciphertext block before being encrypted.
    /// This creates a dependency between blocks, ensuring that identical plaintext blocks encrypt differently.
    /// CBC requires an initialization vector (IV) which should be random and unique for each encryption.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a block cipher service operating in Cipher-Block-Chaining (CBC) mode with custom padding.
    /// </summary>
    /// <remarks>
    /// In CBC mode, each plaintext block is XORed with the previous ciphertext block before being encrypted.
    /// This overload allows specifying a custom padding scheme for handling data that isn't aligned to block boundaries.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="paddingFactory">Factory function that creates the padding mechanism to use for incomplete blocks.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateCbcService(Func<IBlockCipher> engineFactory, Func<IBlockCipherPadding> paddingFactory, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a block cipher service operating in Segmented Integer Counter (SIC) mode, also known as CTR mode.
    /// </summary>
    /// <remarks>
    /// SIC/CTR mode turns a block cipher into a stream cipher. It generates a keystream by encrypting
    /// successive values of a counter and XORing the result with the plaintext.
    /// This mode offers parallelizability and does not require padding mechanisms.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateSicService(Func<IBlockCipher> engineFactory, int bufferSize = 4096);
    
    /// <summary>
    /// Creates a block cipher service operating in Galois/Counter Mode (GCM).
    /// </summary>
    /// <remarks>
    /// GCM combines Counter mode encryption with Galois authentication, providing both data privacy and integrity.
    /// It's an authenticated encryption mode that produces an authentication tag which verifies data integrity.
    /// GCM is widely used for efficient authenticated encryption in secure communications.
    /// </remarks>
    /// <param name="engineFactory">Factory function that creates the underlying block cipher algorithm implementation.</param>
    /// <param name="bufferSize">Size of the internal buffer used for processing data, in bytes. Defaults to 4096.</param>
    /// <returns>A configured block cipher service ready for encryption/decryption operations.</returns>
    IBlockCipherService CreateGcmService(Func<IBlockCipher> engineFactory, int bufferSize = 4096);
}