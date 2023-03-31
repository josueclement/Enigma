using Enigma.PQC;
using NUnit.Framework;
using System.IO;

namespace UnitTests.PQC
{
    internal class KyberTests
    {
        [Test]
        public void SaveAndLoadPublicKey()
        {
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out var publicKey, out _);
            byte[] publicData = publicKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePublicKeyToPEM(publicKey, Kyber.KYBER1024_AES, ms);
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
        public void SaveAndLoadPrivateKey()
        {
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePrivateKeyToPEM(privateKey, Kyber.KYBER1024_AES, ms);
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
        public void SaveAndLoadPrivateKeyWithPassword()
        {
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Kyber.SavePrivateKeyToPEM(privateKey, Kyber.KYBER1024_AES, ms, "test1234ABC");
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
        public void GenerateAndExtract()
        {
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out var publicKey, out var privateKey);
            Kyber.Generate(publicKey, out byte[] clearKey, out byte[] encryptedKey);
            byte[] decryptedKey = Kyber.Extract(privateKey, encryptedKey);
            Assert.That(decryptedKey, Is.EqualTo(clearKey));
        }

        [Test]
        public void GenerateAndExtractWithWrongKey()
        {
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out var publicKey, out _);
            Kyber.GenerateKeyPair(Kyber.KYBER1024_AES, out _, out var privateKey);
            Kyber.Generate(publicKey, out byte[] clearKey, out byte[] encryptedKey);
            byte[] decryptedKey = Kyber.Extract(privateKey, encryptedKey);
            Assert.That(decryptedKey, Is.Not.EqualTo(clearKey));
        }
    }
}
