using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using Enigma.Padding;
using NUnit.Framework;

namespace UnitTests.Padding
{
    public class AnsiX923Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Pad(Tuple<byte[], byte[]> values)
        {
            byte[] padded = AnsiX923Padding.Instance.Pad(values.Item1, 16);
            Assert.That(padded, Is.EqualTo(values.Item2));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Unpad(Tuple<byte[], byte[]> values)
        {
            byte[] unpadded = AnsiX923Padding.Instance.Unpad(values.Item2, 16);
            Assert.That(unpadded, Is.EqualTo(values.Item1));
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                AnsiX923Padding.Instance.Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                AnsiX923Padding.Instance.Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                AnsiX923Padding.Instance.Unpad(Hex.Decode("000000000000000000000000000000"), 16);
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Padding\ansix923.csv"))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                {
                    sr.ReadLine();

                    while (!sr.EndOfStream)
                    {
                        string line = sr.ReadLine();

                        if (line != null)
                        {
                            string[] split = line.Split(',');
                            if (split.Length == 2)
                            {
                                byte[] data = Hex.Decode(split[0]);
                                byte[] padded = Hex.Decode(split[1]);

                                yield return new Tuple<byte[], byte[]>(data, padded);
                            }
                        }
                    }
                }
            }
        }
    }
}
