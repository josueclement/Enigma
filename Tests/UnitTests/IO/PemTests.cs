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
            string dataStr = "345345In the [MHS] model, a user is a person or a computer application.  A user is referred to as either an originator (when sending a message) or a recipient (when receiving one).  MH Service elements define the set of message types and the capabilities that enable an originator to transfer messages of those types to one or more recipients.";
            byte[] data = Encoding.UTF8.GetBytes(dataStr);

            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Owner",
                    Value = "Josué Clément"
                },
                new PemHeaderItem
                {
                    Name = "Key-Type",
                    Value = "Kyber1024-aes"
                },
                new PemHeaderItem
                {
                    Name = "Security",
                    Value = "AES-CBC",
                    Data = data
                }
            };



            PemWriter.Write("Test data", data, @"C:\Temp\test.pem");
            PemWriter.Write("Test data", header, data, @"C:\Temp\test2.pem");

            PemContent c1 = PemReader.Read(@"C:\Temp\test.pem");
            PemContent c2 = PemReader.Read(@"C:\Temp\test2.pem");
        }
    }
}
