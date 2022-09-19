using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Enigma.IO;
using Enigma.Padding;
using Enigma.SymKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.SymKey
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

        [Test]
        public void EncryptCBCNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void EncryptCBCNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void EncryptCBCNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptCBCNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void DecryptCBCNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void DecryptCBCNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void EncryptCBCStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(new MemoryStream(), new MemoryStream(), null, EmptyArr, new NoPadding());
            });
        }

        [Test]
        public void EncryptCBCStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(new MemoryStream(), new MemoryStream(), EmptyArr, null, new NoPadding());
            });
        }

        [Test]
        public void EncryptCBCStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(null, new MemoryStream(), EmptyArr, EmptyArr, new NoPadding());
            });
        }

        [Test]
        public void EncryptCBCStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.EncryptCBC(new MemoryStream(), null, EmptyArr, EmptyArr, new NoPadding());
            });
        }

        [Test]
        public void DecryptCBCStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(new MemoryStream(), new MemoryStream(), null, EmptyArr, new NoPadding());
            });
        }

        [Test]
        public void DecryptCBCStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(new MemoryStream(), new MemoryStream(), EmptyArr, null, new NoPadding());
            });
        }

        [Test]
        public void DecryptCBCStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(null, new MemoryStream(), EmptyArr, EmptyArr, new NoPadding());
            });
        }

        [Test]
        public void DecryptCBCStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                DES.DecryptCBC(new MemoryStream(), null, EmptyArr, EmptyArr, new NoPadding());
            });
        }

        static IEnumerable<Tuple<byte[], byte[], byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\SymKey\des.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] key = BinaryHelper.ReadLV(fs);
                    byte[] iv = BinaryHelper.ReadLV(fs);
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] enc = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], byte[], byte[], byte[]>(key, iv, data, enc);
                }
            }
        }
    }
}
