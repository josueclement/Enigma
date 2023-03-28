using System.IO;
using System.Text;

namespace Enigma.IO
{
    /// <summary>
    /// Helper class to read PEM files
    /// </summary>
    public static class PemReader
    {
        /// <summary>
        /// Read PEM from a <see cref="TextReader"/>
        /// </summary>
        /// <param name="reader">TextReader</param>
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        public static void Read(TextReader reader, out string type, out byte[] data)
        {
            string line;
            type = string.Empty;

            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith("-----BEGIN ") && line.EndsWith("-----"))
                {
                    int endPos = line.LastIndexOf("-----");
                    type = line.Substring(11, endPos - 11);
                    break;
                }
            }

            StringBuilder sb = new StringBuilder();

            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith("-----"))
                    break;
                sb.Append(line.Trim());
            }

            data = Base64.Decode(sb.ToString());
        }

        /// <summary>
        /// Read PEM from a stream
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        public static void Read(Stream input, out string type, out byte[] data)
        {
            using (StreamReader sr = new StreamReader(input, Encoding.UTF8))
            {
                Read(sr, out type, out data);
            }
        }

        /// <summary>
        /// Read PEM from a file
        /// </summary>
        /// <param name="filePath">File path</param>
        /// <param name="type">Data type</param>
        /// <param name="data">Data</param>
        public static void Read(string filePath, out string type, out byte[] data)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                Read(fs, out type, out data);
            }
        }
    }
}
