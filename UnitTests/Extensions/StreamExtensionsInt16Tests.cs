using System.IO;
using System.Threading.Tasks;
using Enigma.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsInt16Tests
{
    [Fact]
    public void ReadWriteInt16()
    {
        using var output = new MemoryStream(); 
        output.WriteShort(short.MaxValue);
        output.WriteShort(short.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadShort();
        Assert.Equal(short.MaxValue, result);
        result = input.ReadShort();
        Assert.Equal(short.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteInt16Async()
    {
        using var output = new MemoryStream();
        await output.WriteShortAsync(short.MaxValue);
        await output.WriteShortAsync(short.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadShortAsync();
        Assert.Equal(short.MaxValue, result);
        result = await input.ReadShortAsync();
        Assert.Equal(short.MinValue, result);
    }
    
    [Fact]
    public void ReadWriteUInt16()
    {
        using var output = new MemoryStream();
        output.WriteUShort(ushort.MaxValue);
        output.WriteUShort(ushort.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadUShort();
        Assert.Equal(ushort.MaxValue, result);
        result = input.ReadUShort();
        Assert.Equal(ushort.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteUInt16Async()
    {
        using var output = new MemoryStream();
        await output.WriteUShortAsync(ushort.MaxValue);
        await output.WriteUShortAsync(ushort.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadUShortAsync();
        Assert.Equal(ushort.MaxValue, result);
        result = await input.ReadUShortAsync();
        Assert.Equal(ushort.MinValue, result);
    }
}