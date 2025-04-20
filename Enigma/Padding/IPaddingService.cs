namespace Enigma.Padding;

/// <summary>
/// Defines operations for applying and removing padding to data blocks for cryptographic operations.
/// Padding ensures data blocks meet the required size for block ciphers and similar algorithms.
/// </summary>
public interface IPaddingService
{
    /// <summary>
    /// Applies padding to the input data to ensure it matches the specified block size.
    /// </summary>
    /// <param name="data">The original data bytes to be padded</param>
    /// <param name="blockSize">The required block size in bytes (must be positive)</param>
    /// <returns>A new byte array containing the original data with appropriate padding</returns>
    byte[] Pad(byte[] data, int blockSize);
    
    /// <summary>
    /// Removes padding from previously padded data.
    /// </summary>
    /// <param name="data">The padded data bytes to be processed</param>
    /// <param name="blockSize">The block size in bytes used during padding</param>
    /// <returns>A new byte array with padding removed, containing only the original data</returns>
    byte[] Unpad(byte[] data, int blockSize);
}