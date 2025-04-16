using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Extensions;

/// <summary>
/// Bool stream extensions
/// </summary>
public static class StreamExtensionsBool
{
    /// <summary>
    /// Write bool value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteBool(this Stream stream, bool value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write bool value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteBoolAsync(this Stream stream, bool value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }

    /// <summary>
    /// Read bool value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Bool value</returns>
    /// <exception cref="IOException"></exception>
    public static bool ReadBool(this Stream stream)
    {
        var buffer = new byte[sizeof(bool)];
        if (stream.Read(buffer, 0, sizeof(bool)) != sizeof(bool))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToBoolean(buffer, 0);
    }

    /// <summary>
    /// Asynchronously read bool value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Bool value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<bool> ReadBoolAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(bool)];
        if (await stream.ReadAsync(buffer, 0, sizeof(bool)).ConfigureAwait(false) != sizeof(bool))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToBoolean(buffer, 0);
    } 
}