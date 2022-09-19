using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.IO
{
    public class Base64Tests
    {
        [Test]
        public void EncodeEmpty()
        {
            Assert.AreEqual("", Base64.Encode(new byte[] { }));
        }

        [Test]
        public void DecodeEmpty()
        {
            Assert.AreEqual(new byte[] { }, Base64.Decode(""));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Encode(Tuple<byte[], string> values)
        {
            string encoded = Base64.Encode(values.Item1);
            Assert.AreEqual(values.Item2, encoded);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decode(Tuple<byte[], string> values)
        {
            byte[] decoded = Base64.Decode(values.Item2);
            Assert.AreEqual(values.Item1, decoded);
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

        [Test]
        public void EncodeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Base64.Encode(null);
            });
        }

        [Test]
        public void DecodeNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Base64.Decode(null);
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
