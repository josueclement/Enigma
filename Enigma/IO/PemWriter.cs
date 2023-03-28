using System;
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
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        /// <param name="writer">TextWriter</param>
        public static void Write(string type, byte[] data, TextWriter writer)
        {
            writer.WriteLine($"-----BEGIN {type}-----");

            string dataB64 = Base64.Encode(data);
            for (int i = 0; i < dataB64.Length; i += LINE_LENGTH)
            {
                writer.WriteLine(dataB64.Substring(i, Math.Min(LINE_LENGTH, dataB64.Length - i)));
            }

            writer.WriteLine($"-----END {type}-----");
        }

        /// <summary>
        /// Write PEM into a <see cref="Stream"/>
        /// </summary>
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        /// <param name="output">Output stream</param>
        public static void Write(string type, byte[] data, Stream output)
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.ASCII))
            {
                Write(type, data, sw);
            }
        }

        /// <summary>
        /// Write PEM into a file
        /// </summary>
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        /// <param name="filePath">File path</param>
        public static void Write(string type, byte[] data, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                Write(type, data, fs);
            }
        }
    }
}
