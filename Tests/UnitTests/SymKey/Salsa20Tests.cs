using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.IO;
using Enigma.Padding;
using Enigma.SymKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.SymKey
{
    public class Salsa20Tests
    {
        static byte[] EmptyArr = new byte[] { };

        [TestCaseSource(nameof(DataSource))]
        public void Encrypt(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc = Salsa20.Encrypt(values.Item3, values.Item1, values.Item2);
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decrypt(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec = Salsa20.Decrypt(values.Item4, values.Item1, values.Item2);
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        [TestCaseSource(nameof(DataSource))]
        public void EncryptStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc;
            using (MemoryStream ms = new MemoryStream(values.Item3))
            {
                using (MemoryStream msEnc = new MemoryStream())
                {
                    Salsa20.Encrypt(ms, msEnc, values.Item1, values.Item2);
                    enc = msEnc.ToArray();
                }
            }
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public async Task EncryptStreamAsync(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc;
            using (MemoryStream ms = new MemoryStream(values.Item3))
            {
                using (MemoryStream msEnc = new MemoryStream())
                {
                    await Salsa20.EncryptAsync(ms, msEnc, values.Item1, values.Item2).ConfigureAwait(false);
                    enc = msEnc.ToArray();
                }
            }
            Assert.That(enc, Is.EqualTo(values.Item4));
        }

        [TestCaseSource(nameof(DataSource))]
        public void DecryptStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream ms = new MemoryStream(values.Item4))
            {
                using (MemoryStream msDec = new MemoryStream())
                {
                    Salsa20.Decrypt(ms, msDec, values.Item1, values.Item2);
                    dec = msDec.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        [TestCaseSource(nameof(DataSource))]
        public async Task DecryptStreamAsync(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream ms = new MemoryStream(values.Item4))
            {
                using (MemoryStream msDec = new MemoryStream())
                {
                    await Salsa20.DecryptAsync(ms, msDec, values.Item1, values.Item2).ConfigureAwait(false);
                    dec = msDec.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item3));
        }

        [Test]
        public void EncryptNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void EncryptNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void EncryptNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void DecryptNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void DecryptNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), new MemoryStream(), null, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), new MemoryStream(), EmptyArr, null);
            });
        }

        [Test]
        public void EncryptStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(null, new MemoryStream(), EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), new MemoryStream(), null, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), new MemoryStream(), EmptyArr, null);
            });
        }

        [Test]
        public void DecryptStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(null, new MemoryStream(), EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), null, EmptyArr, EmptyArr);
            });
        }

        static IEnumerable<Tuple<byte[], byte[], byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\SymKey\salsa20.csv"))
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
