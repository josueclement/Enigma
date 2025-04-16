using System.IO;
using System.Threading.Tasks;

namespace Enigma.Extensions;

/// <summary>
/// Tag-Length-Value stream extensions
/// </summary>
public static class StreamExtensionsTagLengthValue
{
    /// <summary>
    /// Write Tag-Length-Value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="tag">Tag</param>
    /// <param name="value">Value</param>
    public static void WriteTagLengthValue(this Stream stream, ushort tag, byte[] value)
    {
        stream.WriteUShort(tag);
        stream.WriteLengthValue(value);
    }
    
    /// <summary>
    /// Asynchronously write Tag-Length-Value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="tag">Tag</param>
    /// <param name="value">Value</param>
    public static async Task WriteTagLengthValueAsync(this Stream stream, ushort tag, byte[] value)
    {
        await stream.WriteUShortAsync(tag).ConfigureAwait(false);
        await stream.WriteLengthValueAsync(value).ConfigureAwait(false);
    }

    /// <summary>
    /// Read Tag-Length-Value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>(Tag, Value)</returns>
    public static (ushort tag, byte[] value) ReadTagLengthValue(this Stream stream)
    {
        var tag = stream.ReadUShort();
        var value = stream.ReadLengthValue();
        return (tag, value);
    }

    /// <summary>
    /// Asynchronously read Tag-Length-Value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>(Tag, Value)</returns>
    public static async Task<(ushort tag, byte[] value)> ReadTagLengthValueAsync(this Stream stream)
    {
        var tag = await stream.ReadUShortAsync().ConfigureAwait(false);
        var value = await stream.ReadLengthValueAsync().ConfigureAwait(false);
        return (tag, value);
    }
}