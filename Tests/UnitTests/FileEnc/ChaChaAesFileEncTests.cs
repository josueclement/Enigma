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

namespace CryptoToolkitUnitTests.FileEnc
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
            Assert.AreEqual(values.Item1, dec);
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
            Assert.AreEqual(values.Item1, dec);
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
            Assert.AreEqual(values.Item1, dec);
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
            Assert.AreEqual(values.Item1, dec);
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
            Assert.AreEqual(data, dec);
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
            Assert.AreEqual(data, dec);
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
            Assert.AreEqual(data, dec);
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
            Assert.AreEqual(data, dec);
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

            Assert.AreEqual(data, dec);
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

            Assert.AreEqual(data, dec);
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

            Assert.AreEqual(data, dec);
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

            Assert.AreEqual(data, dec);
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
                    Assert.AreEqual("CAENCR!", Encoding.ASCII.GetString(header));

                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.AreEqual(0x05, version);

                    byte[] keyNameData = BinaryHelper.ReadLV(ms);
                    Assert.AreEqual("keyname", Encoding.ASCII.GetString(keyNameData));

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

                    Assert.AreEqual(32, chachaKey.Length);
                    Assert.AreEqual(12, chachaNonce.Length);
                    Assert.AreEqual(32, aesKey.Length);
                    Assert.AreEqual(16, aesIv.Length);

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

                        Assert.AreEqual(32, d1.Length);
                        Assert.AreEqual(32, d2.Length);
                        Assert.AreEqual(0, d0.Length);

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);

                        Assert.AreEqual(data, unpad);
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
                    Assert.AreEqual("CAENCR!", Encoding.ASCII.GetString(header));

                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual(0x05, version);

                    byte[] keyNameData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual("keyname", Encoding.ASCII.GetString(keyNameData));

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

                    Assert.AreEqual(32, chachaKey.Length);
                    Assert.AreEqual(12, chachaNonce.Length);
                    Assert.AreEqual(32, aesKey.Length);
                    Assert.AreEqual(16, aesIv.Length);

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

                        Assert.AreEqual(32, d1.Length);
                        Assert.AreEqual(32, d2.Length);
                        Assert.AreEqual(0, d0.Length);

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);

                        Assert.AreEqual(data, unpad);
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
                    Assert.AreEqual("CAENCP!", Encoding.ASCII.GetString(header));

                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.AreEqual(0x05, version);

                    byte[] chachaSalt = BinaryHelper.ReadLV(ms);
                    byte[] chachaNonce = BinaryHelper.ReadLV(ms);
                    byte[] aesSalt = BinaryHelper.ReadLV(ms);
                    byte[] aesIv = BinaryHelper.ReadLV(ms);

                    Assert.AreEqual(16, chachaSalt.Length);
                    Assert.AreEqual(12, chachaNonce.Length);
                    Assert.AreEqual(16, aesSalt.Length);
                    Assert.AreEqual(16, aesIv.Length);

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

                        Assert.AreEqual(32, d1.Length);
                        Assert.AreEqual(32, d2.Length);
                        Assert.AreEqual(0, d0.Length);

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);

                        Assert.AreEqual(data, unpad);
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
                    Assert.AreEqual("CAENCP!", Encoding.ASCII.GetString(header));

                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual(0x05, version);

                    byte[] chachaSalt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] chachaNonce = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] aesSalt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] aesIv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);

                    Assert.AreEqual(16, chachaSalt.Length);
                    Assert.AreEqual(12, chachaNonce.Length);
                    Assert.AreEqual(16, aesSalt.Length);
                    Assert.AreEqual(16, aesIv.Length);

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

                        Assert.AreEqual(32, d1.Length);
                        Assert.AreEqual(32, d2.Length);
                        Assert.AreEqual(0, d0.Length);

                        byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, chachaKey, chachaNonce);
                        byte[] xor = AES.DecryptCBC(d2, aesKey, aesIv);

                        byte[] dec = new byte[rpad.Length];
                        for (int i = 0; i < rpad.Length; i++)
                            dec[i] = (byte)(rpad[i] ^ xor[i]);

                        string hexDec = Hex.Encode(dec);
                        Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));

                        byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);

                        Assert.AreEqual(data, unpad);
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
