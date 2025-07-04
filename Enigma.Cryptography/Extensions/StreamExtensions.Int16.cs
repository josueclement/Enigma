using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Int16 stream extensions
/// </summary>
public static class StreamExtensionsInt16
{
    /// <summary>
    /// Write Int16 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteShort(this Stream stream, short value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write Int16 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteShortAsync(this Stream stream, short value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }
    
    /// <summary>
    /// Read Int16 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Int16 value</returns>
    /// <exception cref="IOException"></exception>
    public static short ReadShort(this Stream stream)
    {
        var buffer = new byte[sizeof(short)];
        if (stream.Read(buffer, 0, sizeof(short)) != sizeof(short))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToInt16(buffer, 0);
    }
    
    /// <summary>
    /// Asynchronously read Int16 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Int16 value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<short> ReadShortAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(short)];
        if (await stream.ReadAsync(buffer, 0, sizeof(short)).ConfigureAwait(false) != sizeof(short))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToInt16(buffer, 0);
    }
    
    /// <summary>
    /// Write unsigned Int16 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteUShort(this Stream stream, ushort value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write unsigned Int16 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteUShortAsync(this Stream stream, ushort value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }
    
    /// <summary>
    /// Read unsigned Int16 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Unsigned Int16 value</returns>
    /// <exception cref="IOException"></exception>
    public static ushort ReadUShort(this Stream stream)
    {
        var buffer = new byte[sizeof(ushort)];
        if (stream.Read(buffer, 0, sizeof(ushort)) != sizeof(ushort))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToUInt16(buffer, 0);
    }
    
    /// <summary>
    /// Asynchronously read unsigned Int16 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Unsigned Int16 value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<ushort> ReadUShortAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(ushort)];
        if (await stream.ReadAsync(buffer, 0, sizeof(ushort)).ConfigureAwait(false) != sizeof(ushort))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToUInt16(buffer, 0);
    }
}