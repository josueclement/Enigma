using Enigma.FileEnc;
using Enigma.IO;
using Enigma.KDF;
using Enigma.Padding;
using Enigma.PubKey;
using Enigma.Random;
using Enigma.SymKey;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests.FileEnc
{
    public class ChaChaAesFileEncTests
    {
        [TestCaseSource(nameof(DataSourceKey))]
        public void DecryptWithKey(Tuple<byte[], byte[]> values)
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key2.pem", "test1234");
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, rsa);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item1));
        }

        [TestCaseSource(nameof(DataSourceKey))]
        public async Task DecryptWithKeyAsync(Tuple<byte[], byte[]> values)
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key2.pem", "test1234");
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item1));
        }

        [TestCaseSource(nameof(DataSourcePass))]
        public void DecryptWithPass(Tuple<byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, "test1234");
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item1));
        }

        [TestCaseSource(nameof(DataSourcePass))]
        public async Task DecryptWithPassAsync(Tuple<byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, "test1234").ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item1));
        }

        [Test]
        public void DecryptStreamWithKey()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key2.pem", "test1234");
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    StreamHelper.WriteStream(input, output);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.enckey.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, rsa);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public async Task DecryptStreamWithKeyAsync()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key2.pem", "test1234");
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await StreamHelper.WriteStreamAsync(input, output).ConfigureAwait(false);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.enckey.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public void DecryptStreamWithPass()
        {
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    StreamHelper.WriteStream(input, output);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.encpass.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, "test1234");
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public async Task DecryptStreamWithPassAsync()
        {
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await StreamHelper.WriteStreamAsync(input, output).ConfigureAwait(false);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy2.encpass.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, "test1234").ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public void EncryptDecryptWithKey()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.GenerateKeyPair(2048);
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Encrypt(input, output, rsa, "keyname");
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, rsa);
                    dec = output.ToArray();
                }
            }

            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public async Task EncryptDecryptWithKeyAsync()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.GenerateKeyPair(2048);
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.EncryptAsync(input, output, rsa, "keyname").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }

            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public void EncryptDecryptWithPass()
        {
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Encrypt(input, output, "blahblah1234");
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Decrypt(input, output, "blahblah1234");
                    dec = output.ToArray();
                }
            }

            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public async Task EncryptDecryptWithPassAsync()
        {
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.EncryptAsync(input, output, "blahblah1234").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.DecryptAsync(input, output, "blahblah1234").ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }

            Assert.That(dec, Is.EqualTo(data));
        }

        [Test]
        public void CheckKeyEncryption()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.GenerateKeyPair(2048);
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Encrypt(input, output, rsa, "keyname");
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(() =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = BinaryHelper.ReadBytes(ms, 7);
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("CAENCR!"));

                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] keyNameData = BinaryHelper.ReadLV(ms);
                    Assert.That(Encoding.ASCII.GetString(keyNameData), Is.EqualTo("keyname"));

                    byte[] encKeyData = BinaryHelper.ReadLV(ms);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] chachaKey, chachaNonce, aesKey, aesIv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        chachaKey = BinaryHelper.ReadLV(msKeyData);
                        chachaNonce = BinaryHelper.ReadLV(msKeyData);
                        aesKey = BinaryHelper.ReadLV(msKeyData);
                        aesIv = BinaryHelper.ReadLV(msKeyData);
                    }

                    Assert.That(chachaKey.Length, Is.EqualTo(32));
                    Assert.That(chachaNonce.Length, Is.EqualTo(12));
                    Assert.That(aesKey.Length, Is.EqualTo(32));
                    Assert.That(aesIv.Length, Is.EqualTo(16));

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    using (MemoryStream msData = new MemoryStream(enc))
                    {
                        byte[] d1 = BinaryHelper.ReadLV(msData);
                        byte[] d2 = BinaryHelper.ReadLV(msData);
                        byte[] d0 = BinaryHelper.ReadLV(msData);

                        Assert.That(d1.Length, Is.EqualTo(32));
                        Assert.That(d2.Length, Is.EqualTo(32));
                        Assert.That(d0.Length, Is.EqualTo(0));

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);

                        Assert.That(unpad, Is.EqualTo(data));
                    }
                }
            });
        }

        [Test]
        public async Task CheckKeyEncryptionAsync()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.GenerateKeyPair(2048);
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.EncryptAsync(input, output, rsa, "keyname").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(async () =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = await BinaryHelper.ReadBytesAsync(ms, 7).ConfigureAwait(false);
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("CAENCR!"));

                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] keyNameData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    Assert.That(Encoding.ASCII.GetString(keyNameData), Is.EqualTo("keyname"));

                    byte[] encKeyData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] chachaKey, chachaNonce, aesKey, aesIv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        chachaKey = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                        chachaNonce = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                        aesKey = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                        aesIv = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                    }

                    Assert.That(chachaKey.Length, Is.EqualTo(32));
                    Assert.That(chachaNonce.Length, Is.EqualTo(12));
                    Assert.That(aesKey.Length, Is.EqualTo(32));
                    Assert.That(aesIv.Length, Is.EqualTo(16));

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    using (MemoryStream msData = new MemoryStream(enc))
                    {
                        byte[] d1 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);
                        byte[] d2 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);
                        byte[] d0 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);

                        Assert.That(d1.Length, Is.EqualTo(32));
                        Assert.That(d2.Length, Is.EqualTo(32));
                        Assert.That(d0.Length, Is.EqualTo(0));

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);

                        Assert.That(unpad, Is.EqualTo(data));
                    }
                }
            });
        }

        [Test]
        public void CheckPassEncryption()
        {
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    ChaChaAesFileEnc.Encrypt(input, output, "test1234abc");
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(() =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = BinaryHelper.ReadBytes(ms, 7);
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("CAENCP!"));

                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] chachaSalt = BinaryHelper.ReadLV(ms);
                    byte[] chachaNonce = BinaryHelper.ReadLV(ms);
                    byte[] aesSalt = BinaryHelper.ReadLV(ms);
                    byte[] aesIv = BinaryHelper.ReadLV(ms);

                    Assert.That(chachaSalt.Length, Is.EqualTo(16));
                    Assert.That(chachaNonce.Length, Is.EqualTo(12));
                    Assert.That(aesSalt.Length, Is.EqualTo(16));
                    Assert.That(aesIv.Length, Is.EqualTo(16));

                    byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", chachaSalt, 60000);
                    byte[] aesKey = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", aesSalt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    using (MemoryStream msData = new MemoryStream(enc))
                    {
                        byte[] d1 = BinaryHelper.ReadLV(msData);
                        byte[] d2 = BinaryHelper.ReadLV(msData);
                        byte[] d0 = BinaryHelper.ReadLV(msData);

                        Assert.That(d1.Length, Is.EqualTo(32));
                        Assert.That(d2.Length, Is.EqualTo(32));
                        Assert.That(d0.Length, Is.EqualTo(0));

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);

                        Assert.That(unpad, Is.EqualTo(data));
                    }
                }
            });
        }

        [Test]
        public async Task CheckPassEncryptionAsync()
        {
            byte[] data = RandomHelper.GenerateBytes(16);
            byte[] enc;
            using (MemoryStream input = new MemoryStream(data))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await ChaChaAesFileEnc.EncryptAsync(input, output, "test1234abc").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(async () =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = await BinaryHelper.ReadBytesAsync(ms, 7).ConfigureAwait(false);
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("CAENCP!"));

                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] chachaSalt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] chachaNonce = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] aesSalt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] aesIv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);

                    Assert.That(chachaSalt.Length, Is.EqualTo(16));
                    Assert.That(chachaNonce.Length, Is.EqualTo(12));
                    Assert.That(aesSalt.Length, Is.EqualTo(16));
                    Assert.That(aesIv.Length, Is.EqualTo(16));

                    byte[] chachaKey = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", chachaSalt, 60000);
                    byte[] aesKey = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", aesSalt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    using (MemoryStream msData = new MemoryStream(enc))
                    {
                        byte[] d1 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);
                        byte[] d2 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);
                        byte[] d0 = await BinaryHelper.ReadLVAsync(msData).ConfigureAwait(false);

                        Assert.That(d1.Length, Is.EqualTo(32));
                        Assert.That(d2.Length, Is.EqualTo(32));
                        Assert.That(d0.Length, Is.EqualTo(0));

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);

                        Assert.That(unpad, Is.EqualTo(data));
                    }
                }
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSourceKey()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\FileEnc\chachaaesfileenc_key.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] enc = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], byte[]>(data, enc);
                }
            }
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSourcePass()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\FileEnc\chachaaesfileenc_pass.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] enc = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], byte[]>(data, enc);
                }
            }
        }
    }
}
