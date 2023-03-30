using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Enigma.IO
{
    /// <summary>
    /// Helper class to write PEM files
    /// </summary>
    public static class PemWriter
    {
        const int LINE_LENGTH = 64;

        /// <summary>
        /// Write PEM with a <see cref="TextWriter"/>
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="data">Data</param>
        /// <param name="writer">TextWriter</param>
        public static void Write(string title, byte[] data, TextWriter writer)
        {
            if (title == null)
                throw new ArgumentNullException("title");
            if (data == null)
                throw new ArgumentNullException("data");
            if (writer == null)
                throw new ArgumentNullException("writer");

            writer.WriteLine($"-----BEGIN {title.ToUpper()}-----");

            WriteBase64Data(data, writer);

            writer.WriteLine($"-----END {title.ToUpper()}-----");
        }

        /// <summary>
        /// Write PEM with a <see cref="TextWriter"/>
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="header">Header</param>
        /// <param name="data">Data</param>
        /// <param name="writer">TextWriter</param>
        public static void Write(string title, IEnumerable<PemHeaderItem> header, byte[] data, TextWriter writer)
        {
            if (title == null)
                throw new ArgumentNullException("title");
            if (header == null)
                throw new ArgumentNullException("header");
            if (data == null)
                throw new ArgumentNullException("data");
            if (writer == null)
                throw new ArgumentNullException("writer");

            writer.WriteLine($"-----BEGIN {title.ToUpper()}-----");

            foreach (PemHeaderItem item in header)
            {
                writer.WriteLine($"{item.Name}: {item.Value}");
                if (item.Data != null)
                    WriteBase64Data(item.Data, writer, " ");
            }

            writer.WriteLine();
            WriteBase64Data(data, writer);

            writer.WriteLine($"-----END {title.ToUpper()}-----");
        }

        /// <summary>
        /// Write PEM into a <see cref="Stream"/>
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="data">Data</param>
        /// <param name="output">Output stream</param>
        public static void Write(string title, byte[] data, Stream output)
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.ASCII))
            {
                Write(title, data, sw);
            }
        }

        /// <summary>
        /// Write PEM into a <see cref="Stream"/>
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="header">Header</param>
        /// <param name="data">Data</param>
        /// <param name="output">Output stream</param>
        public static void Write(string title, IEnumerable<PemHeaderItem> header, byte[] data, Stream output)
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.ASCII))
            {
                Write(title, header, data, sw);
            }
        }

        /// <summary>
        /// Write PEM into a file
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="data">Data</param>
        /// <param name="filePath">File path</param>
        public static void Write(string title, byte[] data, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                Write(title, data, fs);
            }
        }

        /// <summary>
        /// Write PEM into a file
        /// </summary>
        /// <param name="title">PEM title</param>
        /// <param name="header">Header</param>
        /// <param name="data">Data</param>
        /// <param name="filePath">File path</param>
        public static void Write(string title, IEnumerable<PemHeaderItem> header, byte[] data, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                Write(title, header, data, fs);
            }
        }

        private static void WriteBase64Data(byte[] data, TextWriter writer, string prefix = "")
        {
            string dataB64 = Base64.Encode(data);
            for (int i = 0; i < dataB64.Length; i += LINE_LENGTH)
                writer.WriteLine(prefix + dataB64.Substring(i, Math.Min(LINE_LENGTH, dataB64.Length - i)));
        }
    }

    /// <summary>
    /// PEM header item data structure
    /// </summary>
    public class PemHeaderItem
    {
        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// Value
        /// </summary>
        public string? Value { get; set; }

        /// <summary>
        /// Data
        /// </summary>
        public byte[]? Data { get; set; }
    }

    /// <summary>
    /// PEM content data structure
    /// </summary>
    public class PemContent
    {
        /// <summary>
        /// Title
        /// </summary>
        public string? Title { get; set; }

        /// <summary>
        /// Header
        /// </summary>
        public IEnumerable<PemHeaderItem>? Header { get; set; }

        /// <summary>
        /// Data
        /// </summary>
        public byte[]? Data { get; set; }
    }

    /// <summary>
    /// PEM read exception
    /// </summary>
    public class PemReadException : Exception
    {
        /// <summary>
        /// Constructor for <see cref="PemReadException"/>
        /// </summary>
        /// <param name="message">Message</param>
        public PemReadException(string message) : base(message) { }
    }
}
