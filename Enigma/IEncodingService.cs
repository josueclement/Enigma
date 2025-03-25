namespace Enigma;

/// <summary>
/// Definition for encoding services
/// </summary>
public interface IEncodingService
{
    /// <summary>
    /// Encode data
    /// </summary>
    /// <param name="data">Data to encode</param>
    /// <returns>Encoded data</returns>
    string Encode(byte[] data);
    
    /// <summary>
    /// Decode data
    /// </summary>
    /// <param name="data">Data to decode</param>
    /// <returns>Decoded data</returns>
    byte[] Decode(string data);
}