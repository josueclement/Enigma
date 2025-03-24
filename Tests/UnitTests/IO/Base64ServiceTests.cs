using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using NUnit.Framework;

namespace UnitTests.IO
{
    public class Base64ServiceTests
    {
        [Test]
        public void EncodeEmpty()
        {
            Assert.That(Base64.Encode(new byte[] { }), Is.EqualTo(""));
        }

        [Test]
        public void DecodeEmpty()
        {
            Assert.That(Base64.Decode(""), Is.EqualTo(new byte[] { }));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Encode(Tuple<byte[], string> values)
        {
            string encoded = Base64.Encode(values.Item1);
            Assert.That(encoded, Is.EqualTo(values.Item2));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decode(Tuple<byte[], string> values)
        {
            byte[] decoded = Base64.Decode(values.Item2);
            Assert.That(decoded, Is.EqualTo(values.Item1));
        }

        [Test]
        [TestCase("TWF")]
        public void DecodeBadLength(string encoded)
        {
            Assert.Throws<Base64DecodeException>(() =>
            {
                Base64.Decode(encoded);
            });
        }

        [Test]
        [TestCase("TWF(")]
        public void DecodeBadChars(string encoded)
        {
            Assert.Throws<Base64DecodeException>(() =>
            {
                Base64.Decode(encoded);
            });
        }

        static IEnumerable<Tuple<byte[], string>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\IO\b64.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] b64Data = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], string>(data, Encoding.ASCII.GetString(b64Data));
                }
            }
        }
    }
}
