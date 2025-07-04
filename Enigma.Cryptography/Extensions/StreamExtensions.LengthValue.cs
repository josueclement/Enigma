using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Length-Value stream extensions
/// </summary>
public static class StreamExtensionsLengthValue
{
    /// <summary>
    /// Write value length and value
    /// </summary>
    /// <param name="stream">Stream</param>
    /// <param name="value">Value</param>
    public static void WriteLengthValue(this Stream stream, byte[] value)
    {
        stream.WriteInt(value.Length);
        stream.WriteBytes(value);
    }

    /// <summary>
    /// Asynchronously write value length and value
    /// </summary>
    /// <param name="stream">Stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteLengthValueAsync(this Stream stream, byte[] value)
    {
        await stream.WriteIntAsync(value.Length).ConfigureAwait(false);
        await stream.WriteBytesAsync(value).ConfigureAwait(false);
    }

    /// <summary>
    /// Read value length and value
    /// </summary>
    /// <param name="stream">Stream</param>
    /// <returns>Value</returns>
    public static byte[] ReadLengthValue(this Stream stream)
    {
        var length = stream.ReadInt();
        return stream.ReadBytes(length);
    }

    /// <summary>
    /// Asynchronously read value length and value
    /// </summary>
    /// <param name="stream">Stream</param>
    /// <returns>Value</returns>
    public static async Task<byte[]> ReadLengthValueAsync(this Stream stream)
    {
        var length = await stream.ReadIntAsync().ConfigureAwait(false);
        return await stream.ReadBytesAsync(length).ConfigureAwait(false);
    }
}