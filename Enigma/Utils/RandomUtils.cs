using Org.BouncyCastle.Security;

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
    public static byte[] GenerateRandomBytes(int size)
    {
        var sr = new SecureRandom();
        var bytes = new byte[size];
        sr.NextBytes(bytes);
        return bytes;
    }
}