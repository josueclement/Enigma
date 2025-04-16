using System.IO;
using System.Threading.Tasks;
using Enigma.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsLengthValueTests
{
    [Fact]
    public void ReadWriteLengthValue()
    {
        using var output = new MemoryStream();
        output.WriteLengthValue([0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        var result = input.ReadLengthValue();
        Assert.Equal([0, 1, 254, 255], result);
    }
    
    [Fact]
    public async Task ReadWriteLengthValueAsync()
    {
        using var output = new MemoryStream();
        await output.WriteLengthValueAsync([0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        var result = await input.ReadLengthValueAsync();
        Assert.Equal([0, 1, 254, 255], result);
    }
}