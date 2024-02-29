using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Enigma.IO
{
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

    /// <summary>
    /// Helper class to Write and Read PEM
    /// </summary>
    public static class Pem
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

        /// <summary>
        /// Read PEM from a <see cref="TextReader"/>
        /// </summary>
        /// <param name="reader">TextReader</param>
        public static PemContent Read(TextReader reader)
        {
            PemContent content = new PemContent();
            string line;

            line = reader.ReadLine();
            if (line == null || !line.StartsWith("-----BEGIN "))
                throw new PemReadException("Invalid PEM first line");

            if (!line.EndsWith("-----"))
                throw new PemReadException("Invalid PEM first line");

            int endPos = line.LastIndexOf("-----");
            content.Title = line.Substring(11, endPos - 11);

            StringBuilder sb = new StringBuilder();
            bool? containsHeader = null;
            bool? endOfHeader = null;
            List<PemHeaderItem> header = new List<PemHeaderItem>();
            PemHeaderItem? currentHeaderItem = null;

            while ((line = reader.ReadLine()) != null)
            {
                if (line.Contains(":"))
                {
                    if (endOfHeader == true)
                        throw new PemReadException("Header item found after a blank line");

                    containsHeader = true;
                    endOfHeader = false;

                    // Check if data was read before
                    if (sb.Length > 0)
                    {
                        if (currentHeaderItem != null)
                            currentHeaderItem.Data = Base64.Decode(sb.ToString());
                        sb.Clear();
                    }

                    if (currentHeaderItem != null)
                        header.Add(currentHeaderItem);
                    currentHeaderItem = new PemHeaderItem();

                    int pos = line.IndexOf(':');
                    currentHeaderItem.Name = line.Substring(0, pos);
                    currentHeaderItem.Value = line.Substring(pos + 1).Trim();
                }
                else if (string.IsNullOrWhiteSpace(line))
                {
                    if (containsHeader != true)
                        throw new PemReadException("Blank line found before header or data");
                    endOfHeader = true;

                    if (sb.Length > 0)
                    {
                        if (currentHeaderItem != null)
                            currentHeaderItem.Data = Base64.Decode(sb.ToString());
                        sb.Clear();
                    }

                    if (currentHeaderItem != null)
                        header.Add(currentHeaderItem);

                    content.Header = header;
                }
                else if (line.StartsWith("-----"))
                {
                    if (containsHeader == true && endOfHeader == false)
                        throw new PemReadException("PEM contains header but reached END without blank line");
                    break;
                }
                else
                {
                    sb.Append(line.Trim());
                }
            }

            content.Data = Base64.Decode(sb.ToString());
            return content;
        }

        /// <summary>
        /// Read PEM from a stream
        /// </summary>
        /// <param name="input">Input stream</param>
        public static PemContent Read(Stream input)
        {
            using (StreamReader sr = new StreamReader(input, Encoding.UTF8))
            {
                return Read(sr);
            }
        }

        /// <summary>
        /// Read PEM from a file
        /// </summary>
        /// <param name="filePath">File path</param>
        public static PemContent Read(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return Read(fs);
            }
        }
    }
}
