using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Enigma.DataEncoding;
using Enigma.Hash;

namespace UnitTests.Hash;

public class Md5ServiceTests
{
    [Fact]
    public async Task HashStreamTest()
    {
        var srvc = new Md5Service();
        var hex = new HexService();
        
        var expectedHash = hex.Decode(await File.ReadAllTextAsync(@"Hash\md5.csv.txt", Encoding.ASCII));
        await using var input = new FileStream(@"Hash\md5.csv", FileMode.Open, FileAccess.Read);
        var hash = await srvc.HashAsync(input);
        Assert.Equal(expectedHash, hash);
    }

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvTest(byte[] data, byte[] expectedHash)
    {
        var srvc = new Md5Service();
        var hash = srvc.Hash(data);
        Assert.Equal(expectedHash, hash);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"Hash\md5.csv")
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