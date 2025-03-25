﻿using Enigma.DataEncoding;
using Enigma.StreamCiphers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace UnitTests.StreamCiphers;

public class ChaCha20ServiceTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvEncryptTest(byte[] key, byte[] nonce, byte[] data, byte[] encrypted)
    {
        var srvc = new ChaCha20Service();
        using var msInput = new MemoryStream(data);
        using var msOutput = new MemoryStream();

        await srvc.EncryptAsync(msInput, msOutput, key, nonce);
        Assert.Equal(encrypted, msOutput.ToArray());
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvDecryptTest(byte[] key, byte[] nonce, byte[] data, byte[] encrypted)
    {
        var srvc = new ChaCha20Service();
        using var msInput = new MemoryStream(encrypted);
        using var msOutput = new MemoryStream();

        await srvc.DecryptAsync(msInput, msOutput, key, nonce);
        Assert.Equal(data, msOutput.ToArray()); 
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"StreamCiphers\chacha20.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // key
                    hex.Decode(values[1]), // nonce
                    hex.Decode(values[2]), // data
                    hex.Decode(values[3]) // encrypted
                };
            });
    }
}