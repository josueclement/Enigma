using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for hash service
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Hash data
    /// </summary>
    /// <param name="data">Data to hash</param>
    /// <returns>Hash</returns>
    byte[] Hash(byte[] data);
    
    /// <summary>
    /// Asynchronously hash input stream data
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <returns>Hash</returns>
    Task<byte[]> HashAsync(Stream input);
}