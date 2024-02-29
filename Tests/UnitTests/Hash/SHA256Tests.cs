﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Enigma.Hash;
using Enigma.IO;
using NUnit.Framework;

namespace UnitTests.Hash
{
    public class SHA256Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = SHA256.Hash(values.Item1);
            Assert.That(Hex.Encode(hash), Is.EqualTo(values.Item2));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha256.csv.txt", Encoding.ASCII);
            byte[] hash = SHA256.Hash(@"data\Hash\sha256.csv");
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha256.csv.txt", Encoding.ASCII);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha256.csv"))
            {
                hash = SHA256.Hash(fs);
            }
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public async Task HashStreamAsync()
        {
            string hashStr = await File.ReadAllTextAsync(@"data\Hash\sha256.csv.txt", Encoding.ASCII).ConfigureAwait(false);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha256.csv"))
            {
                hash = await SHA256.HashAsync(fs).ConfigureAwait(false);
            }
            Assert.That(Hex.Encode(hash), Is.EqualTo(hashStr));
        }

        [Test]
        public void HashNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Hex.Encode(null);
            });
        }

        static IEnumerable<Tuple<byte[], string>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha256.csv"))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.Default))
                {
                    sr.ReadLine();

                    while (!sr.EndOfStream)
                    {
                        string line = sr.ReadLine();

                        if (line != null)
                        {
                            string[] split = line.Split(',');
                            if (split.Length == 2)
                            {
                                byte[] data = Hex.Decode(split[0]);
                                string hash = split[1];

                                yield return new Tuple<byte[], string>(data, hash);
                            }
                        }
                    }
                }
            }
        }
    }
}
