using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Double stream extensions
/// </summary>
public static class StreamExtensionsDouble
{
    /// <summary>
    /// Write double
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static void WriteDouble(this Stream stream, double value)
    {
        var data = BitConverter.GetBytes(value);
        stream.Write(data, 0, data.Length);
    }
    
    /// <summary>
    /// Asynchronously write double
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Value</param>
    public static async Task WriteDoubleAsync(this Stream stream, double value)
    {
        var data = BitConverter.GetBytes(value);
        await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
    }

    /// <summary>
    /// Read double value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Double value</returns>
    /// <exception cref="IOException"></exception>
    public static double ReadDouble(this Stream stream)
    {
        var buffer = new byte[sizeof(double)];
        if (stream.Read(buffer, 0, sizeof(double)) != sizeof(double))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToDouble(buffer, 0);
    }

    /// <summary>
    /// Asynchronously read double value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Double value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<double> ReadDoubleAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(double)];
        if (await stream.ReadAsync(buffer, 0, sizeof(double)).ConfigureAwait(false) != sizeof(double))
            throw new IOException("Incorrect number of bytes read");
        return BitConverter.ToDouble(buffer, 0);
    }
}