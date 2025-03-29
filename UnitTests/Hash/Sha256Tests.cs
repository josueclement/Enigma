using Enigma.DataEncoding;
using Enigma.Hash;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests.Hash;

public class Sha256Tests
{
    [Fact]
    public async Task HashStreamTest()
    {
        var service = new HashServiceFactory().CreateSha256HashService();
        var hex = new HexService();
        
        var expectedHash = hex.Decode(await File.ReadAllTextAsync(@"Hash\sha256.csv.txt", Encoding.ASCII));
        await using var input = new FileStream(@"Hash\sha256.csv", FileMode.Open, FileAccess.Read);
        var hash = await service.HashAsync(input);
        
        Assert.Equal(expectedHash, hash);
    }

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvTest(byte[] data, byte[] expectedHash)
    {
        var service = new HashServiceFactory().CreateSha256HashService();
        
        using var input = new MemoryStream(data);
        var hash = await service.HashAsync(input);
        
        Assert.Equal(expectedHash, hash);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"Hash\sha256.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // data
                    hex.Decode(values[1]) // expected hash
                };
            });
    }
}