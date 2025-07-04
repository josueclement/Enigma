using System.IO;
using System.Threading.Tasks;
using Enigma.Cryptography.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsInt32Tests
{
    [Fact]
    public void ReadWriteInt32()
    {
        using var output = new MemoryStream(); 
        output.WriteInt(int.MaxValue);
        output.WriteInt(int.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadInt();
        Assert.Equal(int.MaxValue, result);
        result = input.ReadInt();
        Assert.Equal(int.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteInt32Async()
    {
        using var output = new MemoryStream();
        await output.WriteIntAsync(int.MaxValue);
        await output.WriteIntAsync(int.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadIntAsync();
        Assert.Equal(int.MaxValue, result);
        result = await input.ReadIntAsync();
        Assert.Equal(int.MinValue, result);
    }
    
    [Fact]
    public void ReadWriteUInt32()
    {
        using var output = new MemoryStream();
        output.WriteUInt(uint.MaxValue);
        output.WriteUInt(uint.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadUInt();
        Assert.Equal(uint.MaxValue, result);
        result = input.ReadUInt();
        Assert.Equal(uint.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteUInt32Async()
    {
        using var output = new MemoryStream();
        await output.WriteUIntAsync(uint.MaxValue);
        await output.WriteUIntAsync(uint.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadUIntAsync();
        Assert.Equal(uint.MaxValue, result);
        result = await input.ReadUIntAsync();
        Assert.Equal(uint.MinValue, result);
    }
}