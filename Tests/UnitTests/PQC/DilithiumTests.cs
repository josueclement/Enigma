using Enigma.PQC;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace UnitTests.PQC
{
    internal class DilithiumTests
    {
        [Test]
        public void FirstTest()
        {
            Dilithium.GenerateKeyPair(out var publicKey, out var privateKey);
            byte[] message = Encoding.UTF8.GetBytes("test");
            byte[] signature = Dilithium.Sign(message, privateKey);
            bool valid = Dilithium.Verify(message, signature, publicKey);
        }
    }
}
