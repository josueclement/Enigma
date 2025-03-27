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
    /// Create a padding service with Pkcs7
    /// </summary>
    IPaddingService CreatePkcs7PaddingService();
    
    /// <summary>
    /// Create a padding service with Iso7816
    /// </summary>
    IPaddingService CreateIso7816PaddingService();
    
    /// <summary>
    /// Create a padding service with Iso10126
    /// </summary>
    IPaddingService CreateIso10126PaddingService();
    
    /// <summary>
    /// Create a padding service with X9.23
    /// </summary>
    IPaddingService CreateX923PaddingService();
}