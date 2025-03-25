using System.IO;
using System.Threading.Tasks;

namespace Enigma;

/// <summary>
/// Definition for hash services
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Hash size
    /// </summary>
    int HashSize { get; }
    
    /// <summary>
    /// Hash data
    /// </summary>
    /// <param name="data">Data to hash</param>
    /// <returns>Hash</returns>
    byte[] Hash(byte[] data);

    /// <summary>
    /// Asynchronously hash stream
    /// </summary>
    /// <param name="input">Input stream</param>
    Task<byte[]> HashAsync(Stream input);
}