using Enigma.PQC;
using NUnit.Framework;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace UnitTests.PQC
{
    internal class KyberTests
    {
        [Test]
        [TestCase("kyber512")]
        [TestCase("kyber768")]
        [TestCase("kyber1024")]
        public void SaveAndLoadPublicKey(string type)
        {
            Kyber.GenerateKeyPair(type, out var publicKey, out _);
            byte[] publicData = publicKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePublicKeyToPEM(publicKey, type, ms);
                data = ms.ToArray();
            }
            byte[] readPublicData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPublicKey = Kyber.LoadPublicKeyFromPEM(ms);
                readPublicData = readPublicKey.GetEncoded();
            }

            Assert.That(readPublicData, Is.EqualTo(publicData));
        }

        [Test]
        [TestCase("kyber512")]
        [TestCase("kyber768")]
        [TestCase("kyber1024")]
        public void SaveAndLoadPrivateKey(string type)
        {
            Kyber.GenerateKeyPair(type, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePrivateKeyToPEM(privateKey, type, ms);
                data = ms.ToArray();
            }
            byte[] readPrivateData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPrivateKey = Kyber.LoadPrivateKeyFromPEM(ms);
                readPrivateData = readPrivateKey.GetEncoded();
            }

            Assert.That(readPrivateData, Is.EqualTo(privateData));
        }

        [Test]
        [TestCase("kyber512")]
        [TestCase("kyber768")]
        [TestCase("kyber1024")]
        public void SaveAndLoadPrivateKeyWithPassword(string type)
        {
            Kyber.GenerateKeyPair(type, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePrivateKeyToPEM(privateKey, type, ms, "test1234ABC");
                data = ms.ToArray();
            }
            byte[] readPrivateData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPrivateKey = Kyber.LoadPrivateKeyFromPEM(ms, "test1234ABC");
                readPrivateData = readPrivateKey.GetEncoded();
            }

            Assert.That(readPrivateData, Is.EqualTo(privateData));
        }

        [Test]
        [TestCase("kyber512")]
        [TestCase("kyber768")]
        [TestCase("kyber1024")]
        public void GenerateAndExtract(string type)
        {
            Kyber.GenerateKeyPair(type, out var publicKey, out var privateKey);
            Kyber.Generate(publicKey, out byte[] clearKey, out byte[] encryptedKey);
            byte[] decryptedKey = Kyber.Extract(privateKey, encryptedKey);
            Assert.That(decryptedKey, Is.EqualTo(clearKey));
        }

        [Test]
        [TestCase("kyber512")]
        [TestCase("kyber768")]
        [TestCase("kyber1024")]
        public void GenerateAndExtractWithWrongKey(string type)
        {
            Kyber.GenerateKeyPair(type, out var publicKey, out _);
            Kyber.GenerateKeyPair(type, out _, out var privateKey);
            Kyber.Generate(publicKey, out byte[] clearKey, out byte[] encryptedKey);
            byte[] decryptedKey = Kyber.Extract(privateKey, encryptedKey);
            Assert.That(decryptedKey, Is.Not.EqualTo(clearKey));
        }
    }
}
