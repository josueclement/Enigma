using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Extensions;

/// <summary>
/// Float stream extensions
/// </summary>
public static class StreamExtensionsFloat
{
    /// <summary>
    /// Write float value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteFloat(this Stream stream, float value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write float value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteFloatAsync(this Stream stream, float value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }
    
    /// <summary>
    /// Read float value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Float value</returns>
    /// <exception cref="IOException"></exception>
    public static float ReadFloat(this Stream stream)
    {
        var buffer = new byte[sizeof(float)];
        if (stream.Read(buffer, 0, sizeof(float)) != sizeof(float))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToSingle(buffer, 0);
    }
    
    /// <summary>
    /// Asynchronously read float value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Float value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<float> ReadFloatAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(float)];
        if (await stream.ReadAsync(buffer, 0, sizeof(float)).ConfigureAwait(false) != sizeof(float))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToSingle(buffer, 0);
    }
}