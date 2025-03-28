using Enigma.DataEncoding;
using Enigma.KDF;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UnitTests.KDF;

public class Pbkdf2ServiceTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvTest(string password, byte[] salt, byte[] expectedKey)
    {
        var srvc = new Pbkdf2Service();
        var key = srvc.GenerateKey(32, password, salt, 50_000);
        Assert.Equal(expectedKey, key);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"KDF\pbkdf2.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    values[0], // password
                    hex.Decode(values[1]), // salt
                    hex.Decode(values[2]) // expected key
                };
            });
    }
}