using Enigma.Cryptography.DataEncoding;
using Enigma.Cryptography.Hash;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests.Hash;

public class Sha512Tests
{
    [Fact]
    public async Task HashStreamTest()
    {
        var service = new HashServiceFactory().CreateSha512Service();
        var hex = new HexService();
        
        var expectedHash = hex.Decode(await File.ReadAllTextAsync(@"Hash\sha512.csv.txt", Encoding.ASCII));
        await using var input = new FileStream(@"Hash\sha512.csv", FileMode.Open, FileAccess.Read);
        var hash = await service.HashAsync(input);
        
        Assert.Equal(expectedHash, hash);
    }

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvTest(byte[] data, byte[] expectedHash)
    {
        var service = new HashServiceFactory().CreateSha512Service();
        
        using var input = new MemoryStream(data);
        var hash = await service.HashAsync(input);
        
        Assert.Equal(expectedHash, hash);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"Hash\sha512.csv")
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