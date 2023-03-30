using Enigma.IO;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
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

            Pem.Write("Test data", data, @"C:\Temp\test.pem");
            Pem.Write("Test data", header, data, @"C:\Temp\test2.pem");

            using (FileStream fs = new FileStream(@"C:\Temp\test3.pem", FileMode.Create, FileAccess.Write))
            {
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    Pem.Write("test1", new byte[] { 1, 2, 3 }, sw);
                    Pem.Write("test2", new byte[] { 4, 5, 6 }, sw);
                }
            }

            PemContent c1 = Pem.Read(@"C:\Temp\test.pem");
            PemContent c2 = Pem.Read(@"C:\Temp\test2.pem");

            using (FileStream fs = new FileStream(@"C:\Temp\test3.pem", FileMode.Open, FileAccess.Read))
            {
                using(StreamReader sr = new StreamReader(fs))
                {
                    PemContent c3 = Pem.Read(sr);
                    PemContent c4 = Pem.Read(sr);
                }
            }
        }
    }
}
