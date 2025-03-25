using Enigma.DataEncoding;
using Enigma.Hash;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests.Hash;

public class Sha512ServiceTests
{
    [Fact]
    public async Task HashStreamTest()
    {
        var srvc = new Sha512Service();
        var hex = new HexService();
        
        var expectedHash = hex.Decode(await File.ReadAllTextAsync(@"Hash\sha512.csv.txt", Encoding.ASCII));
        await using var input = new FileStream(@"Hash\sha512.csv", FileMode.Open, FileAccess.Read);
        var hash = await srvc.HashAsync(input);
        Assert.Equal(expectedHash, hash);
    }

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvTest(byte[] data, byte[] expectedHash)
    {
        var srvc = new Sha512Service();
        var hash = srvc.Hash(data);
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