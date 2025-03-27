using Enigma.DataEncoding;
using Enigma.Padding;
using Enigma;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Enigma.BlockCiphers;

namespace UnitTests.BlockCiphers;

public class TripleDesCbcTests
{
    private IBufferedCipher GetCipher()
        => new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvEncryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var service = new BlockCipherService(GetCipher);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        
        using var msInput = new MemoryStream(data);
        using var msOutput = new MemoryStream();

        await service.EncryptAsync(msInput, msOutput, parameters, new NoPaddingService());
        
        Assert.Equal(encrypted, msOutput.ToArray());
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvDecryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var service = new BlockCipherService(GetCipher);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);
        
        using var msInput = new MemoryStream(encrypted);
        using var msOutput = new MemoryStream();

        await service.DecryptAsync(msInput, msOutput, parameters, new NoPaddingService());
        
        Assert.Equal(data, msOutput.ToArray()); 
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"BlockCiphers\tripledes-cbc.csv")
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