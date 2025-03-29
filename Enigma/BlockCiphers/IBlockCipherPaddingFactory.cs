using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.BlockCiphers;

/// <summary>
/// Definition for block cipher padding factory
/// </summary>
public interface IBlockCipherPaddingFactory
{
    /// <summary>
    /// Create a padder that adds PKCS7/PKCS5 padding to a block
    /// </summary>
    IBlockCipherPadding CreatePkcs7Padding();
    
    /// <summary>
    /// Create a padder that adds the padding according to the scheme referenced in ISO 7814-4 - scheme 2 from ISO 9797-1.
    /// The first byte is 0x80, rest is 0x00
    /// </summary>
    IBlockCipherPadding CreateIso7816Padding();
    
    /// <summary>
    /// Create a padder that adds ISO10126-2 padding to a block
    /// </summary>
    IBlockCipherPadding CreateIso10126Padding();
    
    /// <summary>
    /// Create a padder that adds X9.23 padding to a block - if a SecureRandom is passed in random padding is assumed,
    /// otherwise padding with zeros is used
    /// </summary>
    IBlockCipherPadding CreateX923Padding();
}