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
    public class SHA3Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = SHA3.Hash(values.Item1);
            Assert.That(Hex.Encode(hash), Is.EqualTo(values.Item2));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha3.dat.txt", Encoding.ASCII);
            byte[] hash = SHA3.Hash(@"data\Hash\sha3.dat");
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha3.dat.txt", Encoding.ASCII);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha3.dat"))
            {
                hash = SHA3.Hash(fs);
            }
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public async Task HashStreamAsync()
        {
            string hashStr = await File.ReadAllTextAsync(@"data\Hash\sha3.dat.txt", Encoding.ASCII).ConfigureAwait(false);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha3.dat"))
            {
                hash = await SHA3.HashAsync(fs).ConfigureAwait(false);
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
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha3.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] sha3Data = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], string>(data, Encoding.ASCII.GetString(sha3Data));
                }
            }
        }
    }
}
