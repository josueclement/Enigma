using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Extensions;

/// <summary>
/// Int64 stream extensions
/// </summary>
public static class StreamExtensionsInt64
{
    /// <summary>
    /// Write Int64 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteLong(this Stream stream, long value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write Int64 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteLongAsync(this Stream stream, long value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }

    /// <summary>
    /// Read Int64 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Int64 value</returns>
    /// <exception cref="IOException"></exception>
    public static long ReadLong(this Stream stream)
    {
        var buffer = new byte[sizeof(long)];
        if (stream.Read(buffer, 0, sizeof(long)) != sizeof(long))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToInt64(buffer, 0);
    }
    
    /// <summary>
    /// Asynchronously read Int64 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Int64 value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<long> ReadLongAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(long)];
        if (await stream.ReadAsync(buffer, 0, sizeof(long)).ConfigureAwait(false) != sizeof(long))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToInt64(buffer, 0);
    }
    
    /// <summary>
    /// Write unsigned Int64 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteULong(this Stream stream, ulong value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }

    /// <summary>
    /// Asynchronously write unsigned Int64 value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteULongAsync(this Stream stream, ulong value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }
    
    /// <summary>
    /// Read unsigned Int64 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Unsigned Int64 value</returns>
    /// <exception cref="IOException"></exception>
    public static ulong ReadULong(this Stream stream)
    {
        var buffer = new byte[sizeof(ulong)];
        if (stream.Read(buffer, 0, sizeof(ulong)) != sizeof(ulong))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToUInt64(buffer, 0);
    }
    
    /// <summary>
    /// Asynchronously read unsigned Int64 value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Unsigned Int64 value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<ulong> ReadULongAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(ulong)];
        if (await stream.ReadAsync(buffer, 0, sizeof(ulong)).ConfigureAwait(false) != sizeof(ulong))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToUInt64(buffer, 0);
    }
}