using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsTagLengthValueTests
{
    [Fact]
    public void ReadWriteTagLengthValue()
    {
        using var output = new MemoryStream();
        output.WriteTagLengthValue(255, [0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        var (tag, value) = input.ReadTagLengthValue();
        Assert.Equal(255, tag); 
        Assert.Equal([0, 1, 254, 255], value);
    }
    
    [Fact]
    public async Task ReadWriteTagLengthValueAsync()
    {
        using var output = new MemoryStream();
        await output.WriteTagLengthValueAsync(255, [0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        var (tag, value) = await input.ReadTagLengthValueAsync();
        Assert.Equal(255, tag); 
        Assert.Equal([0, 1, 254, 255], value);
    }
}