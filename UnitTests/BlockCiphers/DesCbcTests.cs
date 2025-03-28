using Enigma.DataEncoding;
using Enigma.BlockCiphers;
using Enigma.Padding;
using Org.BouncyCastle.Crypto.Parameters;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace UnitTests.BlockCiphers;

public class DesCbcTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvEncryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcBlockCipherService(engineFactory.CreateDesEngine);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        var padding = new PaddingServiceFactory().CreateNoPaddingService();
        
        using var msInput = new MemoryStream(data);
        using var msOutput = new MemoryStream();

        await service.EncryptAsync(msInput, msOutput, parameters, padding);
        
        Assert.Equal(encrypted, msOutput.ToArray());
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvDecryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcBlockCipherService(engineFactory.CreateDesEngine);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        var padding = new PaddingServiceFactory().CreateNoPaddingService();
        
        using var msInput = new MemoryStream(encrypted);
        using var msOutput = new MemoryStream();

        await service.DecryptAsync(msInput, msOutput, parameters, padding);
        
        Assert.Equal(data, msOutput.ToArray()); 
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"BlockCiphers\des-cbc.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // key
                    hex.Decode(values[1]), // iv
                    hex.Decode(values[2]), // data
                    hex.Decode(values[3]) // encrypted
                };
            });
    }
}