using System;
using Enigma.IO;
using Enigma.Padding;
using NUnit.Framework;

namespace UnitTests.Padding
{
    public class Iso10126Tests
    {
        [Test]
        [TestCase("fe")]
        public void Pad(string dataStr)
        {
            byte[] data = Hex.Decode(dataStr);
            byte[] padded = new Iso10126Padding().Pad(data, 16);
            Assert.That(padded.Length == 16 && padded[padded.Length - 1] == 0x0f);
        }

        [Test]
        [TestCase("fe", "fe00000000000000000000000000000f")]
        public void Unpad(string dataStr, string paddedStr)
        {
            byte[] data = Hex.Decode(dataStr);
            byte[] padded = Hex.Decode(paddedStr);

            byte[] calcData = new Iso10126Padding().Unpad(padded, 16);
            Assert.That(calcData, Is.EqualTo(data));
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Iso10126Padding().Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void PadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Iso10126Padding().Pad(null, 16);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Iso10126Padding().Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new Iso10126Padding().Unpad(Hex.Decode("000000000000000000000000000000"), 16);
            });
        }

        [Test]
        public void UnPadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Iso10126Padding().Unpad(null, 16);
            });
        }
    }
}
