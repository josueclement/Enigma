using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsFloatTests
{
    [Fact]
    public void ReadWriteFloat()
    {
        using var output = new MemoryStream();
        output.WriteFloat(float.MaxValue);
        output.WriteFloat(float.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadFloat();
        Assert.Equal(float.MaxValue, result);
        result = input.ReadFloat();
        Assert.Equal(float.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteFloatAsync()
    {
        using var output = new MemoryStream();
        await output.WriteFloatAsync(float.MaxValue);
        await output.WriteFloatAsync(float.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadFloatAsync();
        Assert.Equal(float.MaxValue, result);
        result = await input.ReadFloatAsync();
        Assert.Equal(float.MinValue, result);
    }
}