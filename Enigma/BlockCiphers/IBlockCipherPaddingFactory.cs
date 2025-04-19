using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher padding factory
/// </summary>
public interface IBlockCipherPaddingFactory
{
    /// <summary>
    /// Creates a padder that implements PKCS#7/PKCS#5 padding.
    /// </summary>
    /// <remarks>
    /// PKCS#7 padding fills remaining bytes with the value equal to the number of padding bytes added.
    /// For example, if 3 padding bytes are needed, each will have the value 0x03.
    /// PKCS#5 is functionally identical but specifically for 8-byte blocks.
    /// This is one of the most widely used padding schemes in cryptographic applications.
    /// </remarks>
    /// <returns>An IBlockCipherPadding implementation for PKCS#7/PKCS#5 padding</returns>
    IBlockCipherPadding CreatePkcs7Padding();
    
    /// <summary>
    /// Creates a padder that implements ISO/IEC 7816-4 padding (also known as Method 2 in ISO/IEC 9797-1).
    /// </summary>
    /// <remarks>
    /// In this padding scheme, a byte with value 0x80 is added first, followed by zero or more
    /// bytes with value 0x00 until the block is filled completely.
    /// This scheme is commonly used in smart card applications and is easily recognizable
    /// when examining binary data.
    /// </remarks>
    /// <returns>An IBlockCipherPadding implementation for ISO/IEC 7816-4 padding</returns>
    IBlockCipherPadding CreateIso7816Padding();
    
    /// <summary>
    /// Creates a padder that implements ISO 10126-2 padding.
    /// </summary>
    /// <remarks>
    /// ISO 10126-2 padding fills all but the last byte with random values, and the last byte
    /// indicates the number of padding bytes added (similar to PKCS#7 in this aspect).
    /// This provides better security against padding oracle attacks compared to deterministic
    /// padding schemes, as most padding bytes are randomized.
    /// </remarks>
    /// <returns>An IBlockCipherPadding implementation for ISO 10126-2 padding</returns>
    IBlockCipherPadding CreateIso10126Padding();
    
    /// <summary>
    /// Creates a padder that implements X9.23/ANSI X9.23 padding.
    /// </summary>
    /// <remarks>
    /// X9.23 padding is similar to ISO 10126-2, where all bytes except the last one
    /// are filled with either random data (if a secure random generator is provided)
    /// or zeros. The last byte contains the count of padding bytes added.
    /// This scheme is commonly used in financial applications and was defined by
    /// the American National Standards Institute (ANSI).
    /// </remarks>
    /// <returns>An IBlockCipherPadding implementation for X9.23 padding</returns>
    IBlockCipherPadding CreateX923Padding();
}