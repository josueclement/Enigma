using System.IO;
using System.Threading.Tasks;

namespace Enigma.Extensions;

/// <summary>
/// Bytes stream extensions
/// </summary>
public static class StreamExtensionsBytes
{
   /// <summary>
    /// Write byte value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Byte value</param>
    public static void WriteByte(this Stream stream, byte value)
        => stream.Write([value], 0, 1);
    
    /// <summary>
    /// Asynchronously write byte value
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="value">Byte value</param>
    public static async Task WriteByteAsync(this Stream stream, byte value)
        => await stream.WriteAsync([value], 0, 1).ConfigureAwait(false);

    /// <summary>
    /// Read byte value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Byte value</returns>
    /// <exception cref="IOException"></exception>
    public static byte ReadByte(this Stream stream)
    {
        var buffer = new byte[sizeof(byte)];
        if (stream.Read(buffer, 0, sizeof(byte)) != sizeof(byte))
            throw new IOException("Incorrect number of bytes read");
        return buffer[0];
    }

    /// <summary>
    /// Asynchronously read byte value
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <returns>Byte value</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<byte> ReadByteAsync(this Stream stream)
    {
        var buffer = new byte[sizeof(byte)];
        if (await stream.ReadAsync(buffer, 0, sizeof(byte)).ConfigureAwait(false) != sizeof(byte))
            throw new IOException("Incorrect number of bytes read");
        return buffer[0];
    }
    
    /// <summary>
    /// Write bytes
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="bytes">Bytes</param>
    public static void WriteBytes(this Stream stream, byte[] bytes)
        => stream.Write(bytes, 0, bytes.Length);
    
    /// <summary>
    /// Asynchronously write bytes
    /// </summary>
    /// <param name="stream">Output stream</param>
    /// <param name="bytes">Bytes</param>
    public static async Task WriteBytesAsync(this Stream stream, byte[] bytes)
        => await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
    
    /// <summary>
    /// Read bytes
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <param name="count">Number of bytes to read</param>
    /// <returns>Bytes</returns>
    /// <exception cref="IOException"></exception>
    public static byte[] ReadBytes(this Stream stream, int count)
    {
        var buffer = new byte[count];
        if (stream.Read(buffer, 0, count) != count)
            throw new IOException("Incorrect number of bytes read");
        return buffer;
    }

    /// <summary>
    /// Asynchronously read bytes
    /// </summary>
    /// <param name="stream">Input stream</param>
    /// <param name="count">Number of bytes to read</param>
    /// <returns>Bytes</returns>
    /// <exception cref="IOException"></exception>
    public static async Task<byte[]> ReadBytesAsync(this Stream stream, int count)
    {
        var buffer = new byte[count];
        if (await stream.ReadAsync(buffer, 0, count).ConfigureAwait(false) != count)
            throw new IOException("Incorrect number of bytes read");
        return buffer;
    } 
}