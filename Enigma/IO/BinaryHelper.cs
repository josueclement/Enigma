using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.IO
{
    /// <summary>
    /// Binary helper class. Write and read binary values from streams
    /// </summary>
    public static class BinaryHelper
    {
        /// <summary>
        /// Size of <see cref="Byte"/>
        /// </summary>
        public const int SIZEOF_BYTE = sizeof(byte);
        /// <summary>
        /// Size of <see cref="bool"/>
        /// </summary>
        public const int SIZEOF_BOOL = sizeof(bool);
        /// <summary>
        /// Size of <see cref="Int16"/>
        /// </summary>
        public const int SIZEOF_INT16 = sizeof(Int16);
        /// <summary>
        /// Size of <see cref="UInt16"/>
        /// </summary>
        public const int SIZEOF_UINT16 = sizeof(UInt16);
        /// <summary>
        /// Size of <see cref="Int32"/>
        /// </summary>
        public const int SIZEOF_INT32 = sizeof(Int32);
        /// <summary>
        /// Size of <see cref="UInt32"/>
        /// </summary>
        public const int SIZEOF_UINT32 = sizeof(UInt32);
        /// <summary>
        /// Size of <see cref="Int64"/>
        /// </summary>
        public const int SIZEOF_INT64 = sizeof(Int64);
        /// <summary>
        /// Size of <see cref="UInt64"/>
        /// </summary>
        public const int SIZEOF_UINT64 = sizeof(UInt64);
        /// <summary>
        /// Size of <see cref="float"/>
        /// </summary>
        public const int SIZEOF_FLOAT = sizeof(float);
        /// <summary>
        /// Size of <see cref="double"/>
        /// </summary>
        public const int SIZEOF_DOUBLE = sizeof(double);

        #region Byte

        /// <summary>
        /// Write byte to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Byte value</param>
        public static void Write(Stream stream, byte value)
        {
            stream.Write(new byte[] { value }, 0, SIZEOF_BYTE);
        }

        /// <summary>
        /// Asynchronously write byte to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Byte value</param>
        public static async Task WriteAsync(Stream stream, byte value)
        {
            await stream.WriteAsync(new byte[] { value }, 0, SIZEOF_BYTE).ConfigureAwait(false);
        }

        /// <summary>
        /// Read byte from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static byte ReadByte(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_BYTE];

            if (stream.Read(buffer, 0, SIZEOF_BYTE) != SIZEOF_BYTE)
                throw new IOException("Incorrect number of bytes returned");

            return buffer[0];
        }

        /// <summary>
        /// Asynchronously read byte from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<byte> ReadByteAsync(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_BYTE];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_BYTE).ConfigureAwait(false) != SIZEOF_BYTE)
                throw new IOException("Incorrect number of bytes returned");

            return buffer[0];
        }

        #endregion

        #region Bytes

        /// <summary>
        /// Write bytes to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bytes value</param>
        public static void Write(Stream stream, byte[] value)
        {
            stream.Write(value, 0, value.Length);
        }

        /// <summary>
        /// Asynchronously write bytes to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bytes value</param>
        public static async Task WriteAsync(Stream stream, byte[] value)
        {
            await stream.WriteAsync(value, 0, value.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read bytes from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <param name="nbBytes">Number of bytes to read</param>
        public static byte[] ReadBytes(Stream stream, int nbBytes)
        {
            byte[] buffer = new byte[nbBytes];

            if (stream.Read(buffer, 0, nbBytes) != nbBytes)
                throw new IOException("Incorrect number of bytes returned");

            return buffer;
        }

        /// <summary>
        /// Asynchronously read bytes from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <param name="nbBytes">Number of bytes to read</param>
        public static async Task<byte[]> ReadBytesAsync(Stream stream, int nbBytes)
        {
            byte[] buffer = new byte[nbBytes];

            if (await stream.ReadAsync(buffer, 0, nbBytes).ConfigureAwait(false) != nbBytes)
                throw new IOException("Incorrect number of bytes returned");

            return buffer;
        }

        #endregion

        #region Bool

        /// <summary>
        /// Write bool to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bool value</param>
        public static void Write(Stream stream, bool value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_BOOL);
        }

        /// <summary>
        /// Asynchronously write bool to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bool value</param>
        public static async Task WriteAsync(Stream stream, bool value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_BOOL).ConfigureAwait(false);
        }

        /// <summary>
        /// Read bool from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static bool ReadBool(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_BOOL];

            if (stream.Read(buffer, 0, SIZEOF_BOOL) != SIZEOF_BOOL)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToBoolean(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read bool from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<bool> ReadBoolAsync(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_BOOL];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_BOOL).ConfigureAwait(false) != SIZEOF_BOOL)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToBoolean(buffer, 0);
        }

        #endregion

        #region Int16

        /// <summary>
        /// Write Int16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int16 value</param>
        public static void Write(Stream stream, Int16 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT16);
        }

        /// <summary>
        /// Asynchronously write Int16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int16 value</param>
        public static async Task WriteAsync(Stream stream, Int16 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_INT16).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static Int16 ReadInt16(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT16];

            if (stream.Read(buffer, 0, SIZEOF_INT16) != SIZEOF_INT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt16(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<Int16> ReadInt16Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT16];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_INT16).ConfigureAwait(false) != SIZEOF_INT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt16(buffer, 0);
        }

        #endregion

        #region UInt16

        /// <summary>
        /// Write UInt16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt16 value</param>
        public static void Write(Stream stream, UInt16 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT16);
        }

        /// <summary>
        /// Asynchronously write UInt16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt16 value</param>
        public static async Task WriteAsync(Stream stream, UInt16 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_UINT16).ConfigureAwait(false);
        }

        /// <summary>
        /// Read UInt16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static UInt16 ReadUInt16(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT16];

            if (stream.Read(buffer, 0, SIZEOF_UINT16) != SIZEOF_UINT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt16(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read UInt16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<UInt16> ReadUInt16Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT16];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_UINT16).ConfigureAwait(false) != SIZEOF_UINT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt16(buffer, 0);
        }

        #endregion

        #region Int32

        /// <summary>
        /// Write Int32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int32 value</param>
        public static void Write(Stream stream, Int32 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT32);
        }

        /// <summary>
        /// Asynchronously write Int32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int32 value</param>
        public static async Task WriteAsync(Stream stream, Int32 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_INT32).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static Int32 ReadInt32(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT32];

            if (stream.Read(buffer, 0, SIZEOF_INT32) != SIZEOF_INT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<Int32> ReadInt32Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT32];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_INT32).ConfigureAwait(false) != SIZEOF_INT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt32(buffer, 0);
        }

        #endregion

        #region UInt32

        /// <summary>
        /// Write UInt32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt32 value</param>
        public static void Write(Stream stream, UInt32 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT32);
        }

        /// <summary>
        /// Asynchronously write UInt32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt32 value</param>
        public static async Task WriteAsync(Stream stream, UInt32 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_UINT32).ConfigureAwait(false);
        }

        /// <summary>
        /// Read UInt32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static UInt32 ReadUInt32(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT32];

            if (stream.Read(buffer, 0, SIZEOF_UINT32) != SIZEOF_UINT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt32(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read UInt32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<UInt32> ReadUInt32Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT32];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_UINT32).ConfigureAwait(false) != SIZEOF_UINT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt32(buffer, 0);
        }

        #endregion

        #region Int64

        /// <summary>
        /// Write Int64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int64 value</param>
        public static void Write(Stream stream, Int64 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT64);
        }

        /// <summary>
        /// Asynchronously write Int64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int64 value</param>
        public static async Task WriteAsync(Stream stream, Int64 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_INT64).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static Int64 ReadInt64(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT64];

            if (stream.Read(buffer, 0, SIZEOF_INT64) != SIZEOF_INT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<Int64> ReadInt64Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_INT64];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_INT64).ConfigureAwait(false) != SIZEOF_INT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt64(buffer, 0);
        }

        #endregion

        #region UInt64

        /// <summary>
        /// Write UInt64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt64 value</param>
        public static void Write(Stream stream, UInt64 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT64);
        }

        /// <summary>
        /// Asynchronously write UInt64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt64 value</param>
        public static async Task WriteAsync(Stream stream, UInt64 value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_UINT64).ConfigureAwait(false);
        }

        /// <summary>
        /// Read UInt64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static UInt64 ReadUInt64(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT64];

            if (stream.Read(buffer, 0, SIZEOF_UINT64) != SIZEOF_UINT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt64(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read UInt64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<UInt64> ReadUInt64Async(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_UINT64];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_UINT64).ConfigureAwait(false) != SIZEOF_UINT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt64(buffer, 0);
        }

        #endregion

        #region float

        /// <summary>
        /// Write float to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">float value</param>
        public static void Write(Stream stream, float value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_FLOAT);
        }

        /// <summary>
        /// Asynchronously write float to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">float value</param>
        public static async Task WriteAsync(Stream stream, float value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_FLOAT).ConfigureAwait(false);
        }

        /// <summary>
        /// Read float from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static float ReadFloat(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_FLOAT];

            if (stream.Read(buffer, 0, SIZEOF_FLOAT) != SIZEOF_FLOAT)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToSingle(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read float from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<float> ReadFloatAsync(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_FLOAT];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_FLOAT).ConfigureAwait(false) != SIZEOF_FLOAT)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToSingle(buffer, 0);
        }

        #endregion

        #region double

        /// <summary>
        /// Write double to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">double value</param>
        public static void Write(Stream stream, double value)
        {
            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_DOUBLE);
        }

        /// <summary>
        /// Asynchronously write double to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">double value</param>
        public static async Task WriteAsync(Stream stream, double value)
        {
            byte[] data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, SIZEOF_DOUBLE).ConfigureAwait(false);
        }

        /// <summary>
        /// Read double from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static double ReadDouble(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_DOUBLE];

            if (stream.Read(buffer, 0, SIZEOF_DOUBLE) != SIZEOF_DOUBLE)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToDouble(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read double from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<double> ReadDoubleAsync(Stream stream)
        {
            byte[] buffer = new byte[SIZEOF_DOUBLE];

            if (await stream.ReadAsync(buffer, 0, SIZEOF_DOUBLE).ConfigureAwait(false) != SIZEOF_DOUBLE)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToDouble(buffer, 0);
        }

        #endregion

        #region string

        /// <summary>
        /// Write string to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">String value</param>
        /// <param name="encoding">String encoding</param>
        public static void Write(Stream stream, string value, Encoding encoding)
        {
            byte[] data = encoding.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write string to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">String value</param>
        /// <param name="encoding">String encoding</param>
        public static async Task WriteAsync(Stream stream, string value, Encoding encoding)
        {
            byte[] data = encoding.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        #endregion

        #region Length-Value

        /// <summary>
        /// Write a Length-Value
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Value</param>
        public static void WriteLV(Stream stream, byte[] value)
        {
            Write(stream, value.Length);
            Write(stream, value);
        }

        /// <summary>
        /// Asynchronously write a Length-Value
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Value</param>
        public static async Task WriteLVAsync(Stream stream, byte[] value)
        {
            Write(stream, value.Length);
            await WriteAsync(stream, value).ConfigureAwait(false);
        }

        /// <summary>
        /// Read a Length-Value
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static byte[] ReadLV(Stream stream)
        {
            int valueLength = ReadInt32(stream);
            return ReadBytes(stream, valueLength);
        }

        /// <summary>
        /// Asynchronously read a Length-Value
        /// </summary>
        /// <param name="stream">Input stream</param>
        public static async Task<byte[]> ReadLVAsync(Stream stream)
        {
            int valueLength = ReadInt32(stream);
            return await ReadBytesAsync(stream, valueLength).ConfigureAwait(false);
        }

        #endregion
    }
}
