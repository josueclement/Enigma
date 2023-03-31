using Enigma.PQC;
using Enigma.Random;
using NUnit.Framework;
using System.IO;

namespace UnitTests.PQC
{
    internal class DilithiumTests
    {
        [Test]
        public void SaveAndLoadPublicKey()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out var publicKey, out _);
            byte[] publicData = publicKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Dilithium.SavePublicKeyToPEM(publicKey, Dilithium.DILITHIUM5_AES, ms);
                data = ms.ToArray();
            }
            byte[] readPublicData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPublicKey = Dilithium.LoadPublicKeyFromPEM(ms);
                readPublicData = readPublicKey.GetEncoded();
            }

            Assert.That(readPublicData, Is.EqualTo(publicData));
        }

        [Test]
        public void SaveAndLoadPrivateKey()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Dilithium.SavePrivateKeyToPEM(privateKey, Dilithium.DILITHIUM5_AES, ms);
                data = ms.ToArray();
            }
            byte[] readPrivateData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPrivateKey = Dilithium.LoadPrivateKeyFromPEM(ms);
                readPrivateData = readPrivateKey.GetEncoded();
            }

            Assert.That(readPrivateData, Is.EqualTo(privateData));
        }

        [Test]
        public void SaveAndLoadPrivateKeyWithPassword()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out _, out var privateKey);
            byte[] privateData = privateKey.GetEncoded();

            byte[] data;
            using (MemoryStream ms = new MemoryStream())
            {
                Dilithium.SavePrivateKeyToPEM(privateKey, Dilithium.DILITHIUM5_AES, ms, "test1234ABC");
                data = ms.ToArray();
            }
            byte[] readPrivateData;
            using (MemoryStream ms = new MemoryStream(data))
            {
                var readPrivateKey = Dilithium.LoadPrivateKeyFromPEM(ms, "test1234ABC");
                readPrivateData = readPrivateKey.GetEncoded();
            }

            Assert.That(readPrivateData, Is.EqualTo(privateData));
        }

        [Test]
        public void SignAndVerify()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out var publicKey, out var privateKey);
            byte[] data = RandomHelper.GenerateBytes(32);
            byte[] signature = Dilithium.Sign(data, privateKey);
            bool isValid = Dilithium.Verify(data, signature, publicKey);
            Assert.That(isValid, Is.True);
        }

        [Test]
        public void SignAndVerifyWithWrongKey()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out var publicKey, out _);
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out _, out var privateKey);
            byte[] data = RandomHelper.GenerateBytes(32);
            byte[] signature = Dilithium.Sign(data, privateKey);
            bool isValid = Dilithium.Verify(data, signature, publicKey);
            Assert.That(isValid, Is.False);
        }

        [Test]
        public void SignAndVerifyWithBadData()
        {
            Dilithium.GenerateKeyPair(Dilithium.DILITHIUM5_AES, out var publicKey, out var privateKey);
            byte[] data = RandomHelper.GenerateBytes(32);
            byte[] badData = RandomHelper.GenerateBytes(32);
            byte[] signature = Dilithium.Sign(data, privateKey);
            bool isValid = Dilithium.Verify(badData, signature, publicKey);
            Assert.That(isValid, Is.False);
        }
    }
}
