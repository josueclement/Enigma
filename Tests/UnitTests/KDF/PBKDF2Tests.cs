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
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\KDF\pbkdf2.csv"))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                {
                    sr.ReadLine();

                    while (!sr.EndOfStream)
                    {
                        string line = sr.ReadLine();

                        if (line != null)
                        {
                            string[] split = line.Split(',');
                            if (split.Length == 3)
                            {
                                string password = split[0];
                                byte[] salt = Hex.Decode(split[1]);
                                byte[] key = Hex.Decode(split[2]);

                                yield return new Tuple<string, byte[], byte[]>(password, salt, key);
                            }
                        }
                    }
                }
            }
        }
    }
}
