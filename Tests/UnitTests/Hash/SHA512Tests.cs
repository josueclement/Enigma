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
    public class SHA512Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = SHA512.Hash(values.Item1);
            Assert.AreEqual(values.Item2, Hex.Encode(hash));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha512.dat.txt", Encoding.ASCII);
            byte[] hash = SHA512.Hash(@"data\Hash\sha512.dat");
            Assert.AreEqual(hashStr, Hex.Encode(hash));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha512.dat.txt", Encoding.ASCII);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.dat"))
            {
                hash = SHA512.Hash(fs);
            }
            Assert.AreEqual(hashStr, Hex.Encode(hash));
        }

        [Test]
        public async Task HashStreamAsync()
        {
            string hashStr = await File.ReadAllTextAsync(@"data\Hash\sha512.dat.txt", Encoding.ASCII).ConfigureAwait(false);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.dat"))
            {
                hash = await SHA512.HashAsync(fs).ConfigureAwait(false);
            }
            Assert.AreEqual(hashStr, Hex.Encode(hash));
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
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] sha512Data = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], string>(data, Encoding.ASCII.GetString(sha512Data));
                }
            }
        }
    }
}
