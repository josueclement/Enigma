using System;
using Enigma.IO;
using Enigma.Padding;
using NUnit.Framework;

namespace UnitTests.Padding
{
    public class NoPaddingTests
    {
        [Test]
        [TestCase("fe")]
        public void Pad(string dataStr)
        {
            byte[] data = Hex.Decode(dataStr);
            byte[] padded = NoPadding.Instance.Pad(data, 16);
            Assert.That(data == padded);
        }

        [Test]
        [TestCase("fe00000000000000000000000000000f")]
        public void Unpad(string paddedStr)
        {
            byte[] padded = Hex.Decode(paddedStr);

            byte[] calcData = NoPadding.Instance.Unpad(padded, 16);
            Assert.That(calcData, Is.EqualTo(padded));
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                NoPadding.Instance.Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                NoPadding.Instance.Unpad(new byte[] { }, 0);
            });
        }
    }
}
