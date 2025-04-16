using System.IO;
using System.Threading.Tasks;
using Enigma.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsBoolTests
{
    [Fact]
    public void ReadWriteBool()
    {
        using var output = new MemoryStream();
        output.WriteBool(false);
        output.WriteBool(true);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadBool();
        Assert.False(result);
        result = input.ReadBool();
        Assert.True(result);
    }

    [Fact]
    public async Task ReadWriteBoolAsync()
    {
        using var output = new MemoryStream();
        await output.WriteBoolAsync(false);
        await output.WriteBoolAsync(true);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadBoolAsync();
        Assert.False(result); 
        result = await input.ReadBoolAsync();
        Assert.True(result);
    }
}