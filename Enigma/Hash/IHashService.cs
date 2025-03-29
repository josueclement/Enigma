using System.IO;
using System.Threading.Tasks;

namespace Enigma.Hash;

/// <summary>
/// Definition for hash service
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Asynchronously hash input stream data
    /// </summary>
    /// <param name="input">Input stream</param>
    /// <returns>Hash</returns>
    Task<byte[]> HashAsync(Stream input);
}