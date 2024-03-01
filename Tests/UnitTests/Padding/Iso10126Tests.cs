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
            byte[] padded = Iso10126Padding.Instance.Pad(data, 16);
            Assert.That(padded.Length == 16 && padded[padded.Length - 1] == 0x0f);
        }

        [Test]
        [TestCase("fe", "fe00000000000000000000000000000f")]
        public void Unpad(string dataStr, string paddedStr)
        {
            byte[] data = Hex.Decode(dataStr);
            byte[] padded = Hex.Decode(paddedStr);

            byte[] calcData = Iso10126Padding.Instance.Unpad(padded, 16);
            Assert.That(calcData, Is.EqualTo(data));
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                Iso10126Padding.Instance.Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                Iso10126Padding.Instance.Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                Iso10126Padding.Instance.Unpad(Hex.Decode("000000000000000000000000000000"), 16);
            });
        }
    }
}
