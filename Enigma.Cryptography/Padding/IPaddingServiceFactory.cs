namespace Enigma.Cryptography.Padding;

/// <summary>
/// Factory for creating various padding services used in cryptographic operations.
/// </summary>
/// <remarks>
/// This factory provides access to different padding mechanisms commonly used in
/// block cipher operations and other cryptographic functions that require
/// data to be aligned to specific block sizes.
/// </remarks>
public interface IPaddingServiceFactory
{
    /// <summary>
    /// Creates a padding service that performs no padding operations.
    /// </summary>
    /// <returns>A padding service that leaves data unpadded.</returns>
    /// <remarks>
    /// Use this when working with data that is already correctly sized or when
    /// padding is not required/desired for the specific cryptographic operation.
    /// </remarks>
    IPaddingService CreateNoPaddingService();
    
    /// <summary>
    /// Creates a padding service implementing PKCS#7/PKCS#5 padding scheme.
    /// </summary>
    /// <returns>A padding service with PKCS#7/PKCS#5 padding implementation.</returns>
    /// <remarks>
    /// PKCS#7 padding adds N bytes with the value N, where N is the number of
    /// bytes required to complete the block. PKCS#5 is essentially PKCS#7 limited
    /// to 8-byte block sizes. This is one of the most widely used padding schemes.
    /// </remarks>
    IPaddingService CreatePkcs7Service();
    
    /// <summary>
    /// Creates a padding service implementing ISO/IEC 7816-4 padding scheme.
    /// </summary>
    /// <returns>A padding service with ISO 7816-4 padding implementation.</returns>
    /// <remarks>
    /// This padding adds a byte with value 0x80 (10000000) followed by zero bytes (0x00)
    /// to fill the block. This is also known as scheme 2 from ISO 9797-1 and is commonly
    /// used in smart card applications.
    /// </remarks>
    IPaddingService CreateIso7816Service();
    
    /// <summary>
    /// Creates a padding service implementing ISO 10126-2 padding scheme.
    /// </summary>
    /// <returns>A padding service with ISO 10126-2 padding implementation.</returns>
    /// <remarks>
    /// ISO 10126-2 padding fills the padding bytes with random values, with the last
    /// byte indicating the number of padding bytes added. This scheme provides improved
    /// security against certain padding oracle attacks.
    /// </remarks>
    IPaddingService CreateIso10126Service();
    
    /// <summary>
    /// Creates a padding service implementing X9.23 padding scheme.
    /// </summary>
    /// <returns>A padding service with X9.23 padding implementation.</returns>
    /// <remarks>
    /// X9.23 padding fills the padding bytes with zeros (0x00), with the last byte
    /// indicating the number of padding bytes added. When a secure random generator
    /// is provided, random padding bytes are used instead of zeros.
    /// </remarks>
    IPaddingService CreateX923Service();
}