using Enigma.PQC;
using NUnit.Framework;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using System;
using System.Collections.Generic;
using System.Text;

namespace UnitTests.PQC
{
    internal class KyberTests
    {
        [Test]
        public void FirstTest()
        {
            Kyber.GenerateKeyPair(out var publicKey, out var privateKey);
            Kyber.Generate(publicKey, out byte[] clear1, out byte[] cipher1);
            Kyber.Generate(publicKey, out byte[] clear2, out byte[] cipher2);
            byte[] dec1 = Kyber.Extract(privateKey, cipher1);
            byte[] dec2 = Kyber.Extract(privateKey, cipher2);
        }
    }
}
