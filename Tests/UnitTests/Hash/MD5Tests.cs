using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Hash;
using Enigma.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Hash
{
    public class MD5Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = MD5.Hash(values.Item1);
            Assert.That(Hex.Encode(hash), Is.EqualTo(values.Item2));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\md5.dat.txt", Encoding.ASCII);
            byte[] hash = MD5.Hash(@"data\Hash\md5.dat");
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\md5.dat.txt", Encoding.ASCII);
            byte[] hash;
            using(FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.dat"))
            {
                hash = MD5.Hash(fs);
            }
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public async Task HashStreamAsync()
        {
            string hashStr = await File.ReadAllTextAsync(@"data\Hash\md5.dat.txt", Encoding.ASCII).ConfigureAwait(false);
            byte[] hash;
            using(FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.dat"))
            {
                hash = await MD5.HashAsync(fs).ConfigureAwait(false);
            }
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public void HashNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Hex.Encode(null);
            });
        }

        static IEnumerable<Tuple<byte[], string>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] md5Data = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], string>(data, Encoding.ASCII.GetString(md5Data));
                }
            }
        }
    }
}
