using Enigma.IO;
using Enigma.PubKey;
using Enigma.Random;
using NUnit.Framework;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Collections.Generic;
using System.IO;

namespace CryptoToolkitUnitTests.PubKey
{
    internal class RSATests
    {
        [Test]
        public void LoadPemPublic()
        {
            Assert.DoesNotThrow(() =>
            {
                RSA.LoadFromPEM(@"data\PubKey\pub_key1.pem");
            });
        }

        [Test]
        public void LoadPemPrivateWithPassword()
        {
            Assert.DoesNotThrow(() =>
            {
                RSA.LoadFromPEM(@"data\PubKey\pk_key1.pem", "test1234");
            });
        }

        [Test]
        public void LoadPemPrivateWithBadPassword()
        {
            Assert.Throws<PemException>(() =>
            {
                RSA.LoadFromPEM(@"data\PubKey\pk_key1.pem", "test1fff234");
            });
        }

        [Test]
        public void LoadPemPrivateWithNoPassword()
        {
            Assert.Throws<PemException>(() =>
            {
                RSA.LoadFromPEM(@"data\PubKey\pk_key1.pem");
            });
        }

        [Test]
        public void LoadPemPrivateWithoutPassword()
        {
            Assert.DoesNotThrow(() =>
            {
                RSA.LoadFromPEM(@"data\PubKey\pk_key2.pem");
            });
        }

        [Test]
        public void GenerateSaveLoadPemPublic()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa1 = RSA.GenerateKeyPair(2048);
            
            Assert.DoesNotThrow(() =>
            {
                byte[] keyData;
                using (MemoryStream ms = new MemoryStream())
                {
                    RSA.SavePublicKeyToPEM(rsa1, ms);
                    keyData = ms.ToArray();
                }

                using (MemoryStream ms = new MemoryStream(keyData))
                {
                    RSA.LoadFromPEM(ms);
                }
            });
        }

        [Test]
        public void GenerateSaveLoadPemPrivateWithPassword()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa1 = RSA.GenerateKeyPair(2048);
            System.Security.Cryptography.RSACryptoServiceProvider rsa2;
            byte[] data = RandomHelper.GenerateBytes(100);
            byte[] enc = RSA.Encrypt(rsa1, data);
            
            Assert.DoesNotThrow(() =>
            {
                byte[] keyData;
                using (MemoryStream ms = new MemoryStream())
                {
                    RSA.SavePrivateKeyToPEM(rsa1, ms, "test1234abc");
                    keyData = ms.ToArray();
                }

                using (MemoryStream ms = new MemoryStream(keyData))
                {
                    rsa2 = RSA.LoadFromPEM(ms, "test1234abc");
                    byte[] dec = RSA.Decrypt(rsa2, enc);
                }
            });
        }

        [Test]
        public void GenerateSaveLoadPemPrivateWithoutPassword()
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa1 = RSA.GenerateKeyPair(2048);
            System.Security.Cryptography.RSACryptoServiceProvider rsa2;
            byte[] data = RandomHelper.GenerateBytes(100);
            byte[] enc = RSA.Encrypt(rsa1, data);
            
            Assert.DoesNotThrow(() =>
            {
                byte[] keyData;
                using (MemoryStream ms = new MemoryStream())
                {
                    RSA.SavePrivateKeyToPEM(rsa1, ms);
                    keyData = ms.ToArray();
                }

                using (MemoryStream ms = new MemoryStream(keyData))
                {
                    rsa2 = RSA.LoadFromPEM(ms);
                    byte[] dec = RSA.Decrypt(rsa2, enc);
                }
            });
        }

        [TestCaseSource(nameof(DataSource1))]
        public void Decrypt(Tuple<byte[], byte[]> values)
        {
            System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\PubKey\pk_key1.pem", "test1234");

            byte[] dec = RSA.Decrypt(rsa, values.Item2);
            Assert.AreEqual(values.Item1, dec);
        }

        [TestCaseSource(nameof(DataSource2))]
        public void DecryptWithWrongPrivateKey(Tuple<byte[], byte[]> values)
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            {
                System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\PubKey\pk_key1.pem", "test1234");

                byte[] dec = RSA.Decrypt(rsa, values.Item2);
                Assert.AreEqual(values.Item1, dec);
            });
        }

        [TestCaseSource(nameof(DataSource2))]
        public void DecryptWithPublicKey(Tuple<byte[], byte[]> values)
        {
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            {
                System.Security.Cryptography.RSACryptoServiceProvider rsa = RSA.LoadFromPEM(@"data\PubKey\pub_key1.pem");

                byte[] dec = RSA.Decrypt(rsa, values.Item2);
                Assert.AreEqual(values.Item1, dec);
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSource1()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\PubKey\rsa1.dat"))
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

        static IEnumerable<Tuple<byte[], byte[]>> DataSource2()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\PubKey\rsa2.dat"))
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
