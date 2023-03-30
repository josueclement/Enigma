using System.Collections;
using System.Collections.Generic;
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
