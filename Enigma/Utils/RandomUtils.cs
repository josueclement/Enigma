using System.Security.Cryptography;

namespace Enigma.Utils;

/// <summary>
/// Utility class for random data generation
/// </summary>
public static class RandomUtils
{
    /// <summary>
    /// Generate random bytes
    /// </summary>
    /// <param name="size">Number of bytes to generate</param>
    /// <returns>Random bytes</returns>
    //TODO: replace with BouncyCastle utility if exists !
    public static byte[] GenerateRandomBytes(int size)
    {
        using var provider = new RNGCryptoServiceProvider();
        var bytes = new byte[size];
        provider.GetBytes(bytes);
        return bytes;
    }
}