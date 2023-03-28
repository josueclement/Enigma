using Enigma.IO;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoToolkitUnitTests.IO
{
    public class PemTests
    {
        [Test]
        public void TestPem()
        {
            string dataStr = "In the [MHS] model, a user is a person or a computer application.  A user is referred to as either an originator (when sending a message) or a recipient (when receiving one).  MH Service elements define the set of message types and the capabilities that enable an originator to transfer messages of those types to one or more recipients.";
            byte[] data = Encoding.UTF8.GetBytes(dataStr);
            PemWriter.Write("Test data", data, @"C:\Temp\test.pem");
            PemReader.Read(@"C:\Temp\test.pem", out string type, out byte[] rData);
            string result = Encoding.UTF8.GetString(rData);
        }
    }
}
