// using Enigma.PQC;
// using Enigma.Random;
// using NUnit.Framework;
// using System.IO;
//
// namespace UnitTests.PQC
// {
//     internal class DilithiumTests
//     {
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SaveAndLoadPublicKey(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out var publicKey, out _);
//             byte[] publicData = publicKey.GetEncoded();
//
//             byte[] data;
//             using (MemoryStream ms = new MemoryStream())
//             {
//                 Dilithium.SavePublicKeyToPEM(publicKey, type, ms);
//                 data = ms.ToArray();
//             }
//             byte[] readPublicData;
//             using (MemoryStream ms = new MemoryStream(data))
//             {
//                 var readPublicKey = Dilithium.LoadPublicKeyFromPEM(ms);
//                 readPublicData = readPublicKey.GetEncoded();
//             }
//
//             Assert.That(readPublicData, Is.EqualTo(publicData));
//         }
//
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SaveAndLoadPrivateKey(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out _, out var privateKey);
//             byte[] privateData = privateKey.GetEncoded();
//
//             byte[] data;
//             using (MemoryStream ms = new MemoryStream())
//             {
//                 Dilithium.SavePrivateKeyToPEM(privateKey, type, ms);
//                 data = ms.ToArray();
//             }
//             byte[] readPrivateData;
//             using (MemoryStream ms = new MemoryStream(data))
//             {
//                 var readPrivateKey = Dilithium.LoadPrivateKeyFromPEM(ms);
//                 readPrivateData = readPrivateKey.GetEncoded();
//             }
//
//             Assert.That(readPrivateData, Is.EqualTo(privateData));
//         }
//
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SaveAndLoadPrivateKeyWithPassword(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out _, out var privateKey);
//             byte[] privateData = privateKey.GetEncoded();
//
//             byte[] data;
//             using (MemoryStream ms = new MemoryStream())
//             {
//                 Dilithium.SavePrivateKeyToPEM(privateKey, type, ms, "test1234ABC");
//                 data = ms.ToArray();
//             }
//             byte[] readPrivateData;
//             using (MemoryStream ms = new MemoryStream(data))
//             {
//                 var readPrivateKey = Dilithium.LoadPrivateKeyFromPEM(ms, "test1234ABC");
//                 readPrivateData = readPrivateKey.GetEncoded();
//             }
//
//             Assert.That(readPrivateData, Is.EqualTo(privateData));
//         }
//
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SignAndVerify(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out var publicKey, out var privateKey);
//             byte[] data = RandomHelper.GenerateBytes(32);
//             byte[] signature = Dilithium.Sign(data, privateKey);
//             bool isValid = Dilithium.Verify(data, signature, publicKey);
//             Assert.That(isValid, Is.True);
//         }
//
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SignAndVerifyWithWrongKey(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out var publicKey, out _);
//             Dilithium.GenerateKeyPair(type, out _, out var privateKey);
//             byte[] data = RandomHelper.GenerateBytes(32);
//             byte[] signature = Dilithium.Sign(data, privateKey);
//             bool isValid = Dilithium.Verify(data, signature, publicKey);
//             Assert.That(isValid, Is.False);
//         }
//
//         [Test]
//         [TestCase("dilithium2")]
//         [TestCase("dilithium3")]
//         [TestCase("dilithium5")]
//         public void SignAndVerifyWithBadData(string type)
//         {
//             Dilithium.GenerateKeyPair(type, out var publicKey, out var privateKey);
//             byte[] data = RandomHelper.GenerateBytes(32);
//             byte[] badData = RandomHelper.GenerateBytes(32);
//             byte[] signature = Dilithium.Sign(data, privateKey);
//             bool isValid = Dilithium.Verify(badData, signature, publicKey);
//             Assert.That(isValid, Is.False);
//         }
//     }
// }
