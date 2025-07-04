using Enigma.Cryptography.DataEncoding;
using Enigma.Cryptography.Padding;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UnitTests.Padding;

public class Pkcs7PaddingTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvPadTest(byte[] data, byte[] paddedData)
    {
        var service = new PaddingServiceFactory().CreatePkcs7Service();
        
        var padded = service.Pad(data, 16);
        
        Assert.Equal(paddedData, padded);
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvUnpadTest(byte[] data, byte[] paddedData)
    {
        var service = new PaddingServiceFactory().CreatePkcs7Service();
        
        var unpaddedData = service.Unpad(paddedData, 16);
        
        Assert.Equal(data, unpaddedData);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"Padding\pkcs7.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // data
                    hex.Decode(values[1]), // padded
                };
            });
    }
}