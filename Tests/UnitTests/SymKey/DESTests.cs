using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.IO;
using Enigma.Padding;
using Enigma.SymKey;
using NUnit.Framework;

namespace UnitTests.SymKey
{
    public class DESTests
    {
        static byte[] EmptyArr = new byte[] { };

        [TestCaseSource(nameof(DataSource))]
        public void EncryptCBC(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc = DES.EncryptCBC(values.Item3, values.Item1, values.Item2);
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public void DecryptCBC(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec = DES.DecryptCBC(values.Item4, values.Item1, values.Item2);
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        [TestCaseSource(nameof(DataSource))]
        public void EncryptCBCStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc;
            using (MemoryStream ms = new MemoryStream(values.Item3))
            {
                using (MemoryStream msEnc = new MemoryStream())
                {
                    DES.EncryptCBC(ms, msEnc, values.Item1, values.Item2, new NoPadding());
                    enc = msEnc.ToArray();
                }
            }
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public async Task EncryptCBCStreamAsync(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc;
            using (MemoryStream ms = new MemoryStream(values.Item3))
            {
                using (MemoryStream msEnc = new MemoryStream())
                {
                    await DES.EncryptCBCAsync(ms, msEnc, values.Item1, values.Item2, new NoPadding()).ConfigureAwait(false);
                    enc = msEnc.ToArray();
                }
            }
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public void DecryptCBCStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream ms = new MemoryStream(values.Item4))
            {
                using (MemoryStream msDec = new MemoryStream())
                {
                    DES.DecryptCBC(ms, msDec, values.Item1, values.Item2, new NoPadding());
                    dec = msDec.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        [TestCaseSource(nameof(DataSource))]
        public async Task DecryptCBCStreamAsync(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream ms = new MemoryStream(values.Item4))
            {
                using (MemoryStream msDec = new MemoryStream())
                {
                    await DES.DecryptCBCAsync(ms, msDec, values.Item1, values.Item2, new NoPadding()).ConfigureAwait(false);
                    dec = msDec.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        static IEnumerable<Tuple<byte[], byte[], byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\SymKey\des.csv"))
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
                            if (split.Length == 4)
                            {
                                byte[] key = Hex.Decode(split[0]);
                                byte[] iv = Hex.Decode(split[1]);
                                byte[] data = Hex.Decode(split[2]);
                                byte[] enc = Hex.Decode(split[3]);

                                yield return new Tuple<byte[], byte[], byte[], byte[]>(key, iv, data, enc);
                            }
                        }
                    }
                }
            }
        }
    }
}
