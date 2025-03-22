namespace Enigma;

/// <summary>
/// Definition for padding services
/// </summary>
public interface IPaddingService
{
    /// <summary>
    /// Pad data
    /// </summary>
    /// <param name="data">Data to pad</param>
    /// <param name="blockSize">Block size</param>
    /// <returns>Padded data</returns>
    byte[] Pad(byte[] data, int blockSize);
    
    /// <summary>
    /// Unpad data
    /// </summary>
    /// <param name="data">Data to unpad</param>
    /// <param name="blockSize">Block size</param>
    /// <returns>Unpadded data</returns>
    byte[] UnPad(byte[] data, int blockSize);
}