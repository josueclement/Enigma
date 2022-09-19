using System;
using System.Collections.Generic;
using System.IO;
using Enigma.IO;
using Enigma.Padding;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Padding
{
    public class Iso7816Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Pad(Tuple<byte[], byte[]> values)
        {
            byte[] padded = new Iso7816Padding().Pad(values.Item1, 16);
            Assert.AreEqual(values.Item2, padded);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Unpad(Tuple<byte[], byte[]> values)
        {
            byte[] unpadded = new Iso7816Padding().Unpad(values.Item2, 16);
            Assert.AreEqual(values.Item1, unpadded);
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Iso7816Padding().Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void PadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Iso7816Padding().Pad(null, 16);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Iso7816Padding().Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new Iso7816Padding().Unpad(Hex.Decode("008000000000000000000000000000"), 16);
            });
        }

        [Test]
        public void UnPadBadPaddingData()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new Iso7816Padding().Unpad(Hex.Decode("008000000000000a0000000000000000"), 16);
            });
        }

        [Test]
        public void UnPadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Iso7816Padding().Unpad(null, 16);
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Padding\iso7816.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] padded = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], byte[]>(data, padded);
                }
            }
        }
    }
}
