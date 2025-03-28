namespace Enigma;

/// <summary>
/// Definition for padding service factory
/// </summary>
public interface IPaddingServiceFactory
{
    /// <summary>
    /// Create a padding service for raw values without padding
    /// </summary>
    IPaddingService CreateNoPaddingService();
    
    /// <summary>
    /// Create a padding service with a padder that adds PKCS7/PKCS5 padding to a block.
    /// </summary>
    IPaddingService CreatePkcs7PaddingService();
    
    /// <summary>
    /// Create a padding service with a padder that adds the padding according to the scheme referenced in ISO 7814-4 - scheme 2 from ISO 9797-1.
    /// The first byte is 0x80, rest is 0x00
    /// </summary>
    IPaddingService CreateIso7816PaddingService();
    
    /// <summary>
    /// Create a padding service with a padder that adds ISO10126-2 padding to a block.
    /// </summary>
    IPaddingService CreateIso10126PaddingService();
    
    /// <summary>
    /// Create a padding service with a padder that adds X9.23 padding to a block - if a SecureRandom is passed in random padding is assumed,
    /// otherwise padding with zeros is used.
    /// </summary>
    IPaddingService CreateX923PaddingService();
}