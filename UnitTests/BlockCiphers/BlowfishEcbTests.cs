﻿using Enigma.BlockCiphers;
using Enigma.DataEncoding;
using Enigma.Padding;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace UnitTests.BlockCiphers;

public class BlowfishEcbTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvEncryptTest(byte[] key, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateEcbBlockCipherService(engineFactory.CreateBlowfishEngine);
        var parameters = new KeyParameter(key);
        var padding = new PaddingServiceFactory().CreateNoPaddingService();
        
        using var msInput = new MemoryStream(data);
        using var msOutput = new MemoryStream();

        await service.EncryptAsync(msInput, msOutput, parameters, padding);
        
        Assert.Equal(encrypted, msOutput.ToArray());
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvDecryptTest(byte[] key, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateEcbBlockCipherService(engineFactory.CreateBlowfishEngine);
        var parameters = new KeyParameter(key);
        var padding = new PaddingServiceFactory().CreateNoPaddingService();
        
        using var msInput = new MemoryStream(encrypted);
        using var msOutput = new MemoryStream();

        await service.DecryptAsync(msInput, msOutput, parameters, padding);
        
        Assert.Equal(data, msOutput.ToArray()); 
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"BlockCiphers\blowfish-ecb.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // key
                    hex.Decode(values[1]), // data
                    hex.Decode(values[2]) // encrypted
                };
            });
    }
}