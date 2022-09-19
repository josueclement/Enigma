using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Enigma.IO;
using Enigma.KDF;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.KDF
{
    public class PBKDF2Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void GenerateKeys(Tuple<string, byte[], byte[]> values)
        {
            byte[] key = PBKDF2.GenerateKeyFromPassword(32, values.Item1, values.Item2, 50000);
            Assert.That(key, Is.EqualTo(values.Item3));
        }

        static IEnumerable<Tuple<string, byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\KDF\pbkdf2.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] passwordData = BinaryHelper.ReadLV(fs);
                    byte[] salt = BinaryHelper.ReadLV(fs);
                    byte[] key = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<string, byte[], byte[]>(Encoding.ASCII.GetString(passwordData), salt, key);
                }
            }
        }
    }
}
