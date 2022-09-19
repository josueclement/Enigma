using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.IO
{
    public class HexTests
    {
        [Test]
        public void EncodeEmpty()
        {
            Assert.AreEqual("", Hex.Encode(new byte[] { }));
        }

        [Test]
        public void DecodeEmpty()
        {
            Assert.AreEqual(new byte[] { }, Hex.Decode(""));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Encode(Tuple<byte[], string> values)
        {
            string encoded = Hex.Encode(values.Item1);
            Assert.AreEqual(values.Item2, encoded);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decode(Tuple<byte[], string> values)
        {
            byte[] decoded = Hex.Decode(values.Item2);
            Assert.AreEqual(values.Item1, decoded);
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
