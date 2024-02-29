using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using NUnit.Framework;

namespace UnitTests.IO
{
    public class HexTests
    {
        [Test]
        public void EncodeEmpty()
        {
            Assert.That(Hex.Encode(new byte[] { }), Is.EqualTo(""));
        }

        [Test]
        public void DecodeEmpty()
        {
            Assert.That(Hex.Decode(""), Is.EqualTo(new byte[] { }));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Encode(Tuple<byte[], string> values)
        {
            string encoded = Hex.Encode(values.Item1);
            Assert.That(encoded, Is.EqualTo(values.Item2));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decode(Tuple<byte[], string> values)
        {
            byte[] decoded = Hex.Decode(values.Item2);
            Assert.That(decoded, Is.EqualTo(values.Item1));
        }

        [Test]
        [TestCase("8f0")]
        public void DecodeBadLength(string encoded)
        {
            Assert.Throws<HexDecodeException>(() =>
            {
                Hex.Decode(encoded);
            });
        }

        [Test]
        [TestCase("8f0g")]
        public void DecodeBadChars(string encoded)
        {
            Assert.Throws<HexDecodeException>(() =>
            {
                Hex.Decode(encoded);
            });
        }

        [Test]
        public void EncodeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Hex.Encode(null);
            });
        }

        [Test]
        public void DecodeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Hex.Decode(null);
            });
        }

        static IEnumerable<Tuple<byte[], string>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\IO\hex.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] hexData = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], string>(data, Encoding.ASCII.GetString(hexData));
                }
            }
        }
    }
}
