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
            Assert.That(dec, Is.EqualTo(values.Item1));
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
                    AesFileEnc.Decrypt(input, output, "test1234");
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
                    await AesFileEnc.DecryptAsync(input, output, "test1234").ConfigureAwait(false);
                    dec = output.ToArray();
                }
            }
            Assert.That(dec, Is.EqualTo(values.Item1));
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
            Assert.That(dec, Is.EqualTo(data));
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
            Assert.That(dec, Is.EqualTo(data));
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
            Assert.That(dec, Is.EqualTo(data));
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
                    AesFileEnc.Encrypt(input, output, rsa, "keyname");
                    enc = output.ToArray();
                }
            }

            Assert.Multiple(() =>
            {
                using (MemoryStream ms = new MemoryStream(enc))
                {
                    byte[] header = BinaryHelper.ReadBytes(ms, 6);
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("AENCR!"));
                    
                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] keyNameData = BinaryHelper.ReadLV(ms);
                    Assert.That(Encoding.ASCII.GetString(keyNameData), Is.EqualTo("keyname"));

                    byte[] encKeyData = BinaryHelper.ReadLV(ms);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] key, iv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        key = BinaryHelper.ReadLV(msKeyData);
                        iv = BinaryHelper.ReadLV(msKeyData);
                    }

                    Assert.That(key.Length, Is.EqualTo(32));
                    Assert.That(iv.Length, Is.EqualTo(16));

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    Assert.That(enc.Length, Is.EqualTo(32));
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);
                    Assert.That(unpad, Is.EqualTo(data));
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
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("AENCR!"));
                    
                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] keyNameData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    Assert.That(Encoding.ASCII.GetString(keyNameData), Is.EqualTo("keyname"));

                    byte[] encKeyData = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] keyData = RSA.Decrypt(rsa, encKeyData);

                    byte[] key, iv;
                    using (MemoryStream msKeyData = new MemoryStream(keyData))
                    {
                        key = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                        iv = await BinaryHelper.ReadLVAsync(msKeyData).ConfigureAwait(false);
                    }

                    Assert.That(key.Length, Is.EqualTo(32));
                    Assert.That(iv.Length, Is.EqualTo(16));

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    Assert.That(enc.Length, Is.EqualTo(32));
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);
                    Assert.That(unpad, Is.EqualTo(data));
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
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("AENCP!"));
                    
                    byte version = BinaryHelper.ReadByte(ms);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] salt = BinaryHelper.ReadLV(ms);
                    byte[] iv = BinaryHelper.ReadLV(ms);

                    Assert.That(salt.Length, Is.EqualTo(16));
                    Assert.That(iv.Length, Is.EqualTo(16));
                    byte[] key = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", salt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        StreamHelper.WriteStream(ms, msData);
                        enc = msData.ToArray();
                    }

                    Assert.That(enc.Length, Is.EqualTo(32));
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);
                    Assert.That(unpad, Is.EqualTo(data));
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
                    Assert.That(Encoding.ASCII.GetString(header), Is.EqualTo("AENCP!"));
                    
                    byte version = await BinaryHelper.ReadByteAsync(ms).ConfigureAwait(false);
                    Assert.That(version, Is.EqualTo(0x05));

                    byte[] salt = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                    byte[] iv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);

                    Assert.That(salt.Length, Is.EqualTo(16));
                    Assert.That(iv.Length, Is.EqualTo(16));
                    byte[] key = PBKDF2.GenerateKeyFromPassword(32, "test1234abc", salt, 60000);

                    byte[] enc;
                    using (MemoryStream msData = new MemoryStream())
                    {
                        await StreamHelper.WriteStreamAsync(ms, msData).ConfigureAwait(false);
                        enc = msData.ToArray();
                    }

                    Assert.That(enc.Length, Is.EqualTo(32));
                    byte[] dec = AES.DecryptCBC(enc, key, iv);

                    string hexDec = Hex.Encode(dec);
                    Assert.That(hexDec.EndsWith("10101010101010101010101010101010"));
                    byte[] unpad = Pkcs7Padding.Instance.Unpad(dec, 16);
                    Assert.That(unpad, Is.EqualTo(data));
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
