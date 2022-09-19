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
    public class AesFileEncTests
    {
        [TestCaseSource(nameof(DataSourceKey))]
        public void DecryptWithKey(Tuple<byte[], byte[]> values)
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key1.pem", "test1234");
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    AesFileEnc.Decrypt(input, output, rsa);
                    dec = output.ToArray();
                }
            }
            Assert.AreEqual(values.Item1, dec);
        }

        [TestCaseSource(nameof(DataSourceKey))]
        public async Task DecryptWithKeyAsync(Tuple<byte[], byte[]> values)
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key1.pem", "test1234");
            byte[] dec;
            using (MemoryStream input = new MemoryStream(values.Item2))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await AesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
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
                    AesFileEnc.Decrypt(input, output, "test1234");
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
                    await AesFileEnc.DecryptAsync(input, output, "test1234").ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.AreEqual(values.Item1, dec);
        }

        [Test]
        public void DecryptStreamWithKey()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key1.pem", "test1234");
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    StreamHelper.WriteStream(input, output);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.enckey.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    AesFileEnc.Decrypt(input, output, rsa);
                    dec = output.ToArray();
                }
            }
            Assert.AreEqual(data, dec);
        }

        [Test]
        public async Task DecryptStreamWithKeyAsync()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\FileEnc\pk_key1.pem", "test1234");
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await StreamHelper.WriteStreamAsync(input, output).ConfigureAwait(false);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.enckey.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await AesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.AreEqual(data, dec);
        }

        [Test]
        public void DecryptStreamWithPass()
        {
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    StreamHelper.WriteStream(input, output);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.encpass.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    AesFileEnc.Decrypt(input, output, "test1234");
                    dec = output.ToArray();
                }
            }
            Assert.AreEqual(data, dec);
        }

        [Test]
        public async Task DecryptStreamWithPassAsync()
        {
            byte[] data;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await StreamHelper.WriteStreamAsync(input, output).ConfigureAwait(false);
                    data = output.ToArray();
                }
            }

            byte[] dec;
            using (FileStream input = StreamHelper.GetFileStreamOpen(@"data\FileEnc\dummy.encpass.dat"))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await AesFileEnc.DecryptAsync(input, output, "test1234").ConfigureAwait(false);
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
                    AesFileEnc.Encrypt(input, output, rsa, "keyname");
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    AesFileEnc.Decrypt(input, output, rsa);
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
                    await AesFileEnc.EncryptAsync(input, output, rsa, "keyname").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await AesFileEnc.DecryptAsync(input, output, rsa).ConfigureAwait(false);
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
                    AesFileEnc.Encrypt(input, output, "blahblah1234");
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    AesFileEnc.Decrypt(input, output, "blahblah1234");
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
                    await AesFileEnc.EncryptAsync(input, output, "blahblah1234").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            byte[] dec;
            using (MemoryStream input = new MemoryStream(enc))
            {
                using (MemoryStream output = new MemoryStream())
                {
                    await AesFileEnc.DecryptAsync(input, output, "blahblah1234").ConfigureAwait(false);
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
                    AesFileEnc.Encrypt(input, output, rsa, "keyname");
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(() =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = BinaryHelper.ReadBytes(ms, 6);
                    Assert.AreEqual("AENCR!", Encoding.ASCII.GetString(header));
                    
                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.AreEqual(0x05, version);

                    byte[] keyNameData = BinaryHelper.ReadLV(ms);
                    Assert.AreEqual("keyname", Encoding.ASCII.GetString(keyNameData));

                    byte[] encKeyData = BinaryHelper.ReadLV(ms);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] key, iv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        key = BinaryHelper.ReadLV(msKeyData);
                        iv = BinaryHelper.ReadLV(msKeyData);
                    }

                    Assert.AreEqual(32, key.Length);
                    Assert.AreEqual(16, iv.Length);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    Assert.AreEqual(32, enc.Length);
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);
                    Assert.AreEqual(data, unpad);
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
                    await AesFileEnc.EncryptAsync(input, output, rsa, "keyname").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(async () =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = await BinaryHelper.ReadBytesAsync(ms, 6).ConfigureAwait(false);
                    Assert.AreEqual("AENCR!", Encoding.ASCII.GetString(header));
                    
                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual(0x05, version);

                    byte[] keyNameData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual("keyname", Encoding.ASCII.GetString(keyNameData));

                    byte[] encKeyData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] key, iv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        key = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                        iv = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                    }

                    Assert.AreEqual(32, key.Length);
                    Assert.AreEqual(16, iv.Length);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    Assert.AreEqual(32, enc.Length);
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);
                    Assert.AreEqual(data, unpad);
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
                    AesFileEnc.Encrypt(input, output, "test1234abc");
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(() =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = BinaryHelper.ReadBytes(ms, 6);
                    Assert.AreEqual("AENCP!", Encoding.ASCII.GetString(header));
                    
                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.AreEqual(0x05, version);

                    byte[] salt = BinaryHelper.ReadLV(ms);
                    byte[] iv = BinaryHelper.ReadLV(ms);

                    Assert.AreEqual(16, salt.Length);
                    Assert.AreEqual(16, iv.Length);
                    byte[] key = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", salt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    Assert.AreEqual(32, enc.Length);
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);
                    Assert.AreEqual(data, unpad);
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
                    await AesFileEnc.EncryptAsync(input, output, "test1234abc").ConfigureAwait(false);
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(async () =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = await BinaryHelper.ReadBytesAsync(ms, 6).ConfigureAwait(false);
                    Assert.AreEqual("AENCP!", Encoding.ASCII.GetString(header));
                    
                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.AreEqual(0x05, version);

                    byte[] salt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] iv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);

                    Assert.AreEqual(16, salt.Length);
                    Assert.AreEqual(16, iv.Length);
                    byte[] key = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", salt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    Assert.AreEqual(32, enc.Length);
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = new Pkcs7Padding().Unpad(dec, 16);
                    Assert.AreEqual(data, unpad);
                }
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSourceKey()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\FileEnc\aesfileenc_key.dat"))
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
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\FileEnc\aesfileenc_pass.dat"))
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
