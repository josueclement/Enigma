using System.IO;
using System.Threading.Tasks;
using Enigma.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsInt64Tests
{
    [Fact]
    public void ReadWriteInt64()
    {
        using var output = new MemoryStream(); 
        output.WriteLong(long.MaxValue);
        output.WriteLong(long.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadLong();
        Assert.Equal(long.MaxValue, result);
        result = input.ReadLong();
        Assert.Equal(long.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteInt64Async()
    {
        using var output = new MemoryStream();
        await output.WriteLongAsync(long.MaxValue);
        await output.WriteLongAsync(long.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadLongAsync();
        Assert.Equal(long.MaxValue, result);
        result = await input.ReadLongAsync();
        Assert.Equal(long.MinValue, result);
    }
    
    [Fact]
    public void ReadWriteUInt64()
    {
        using var output = new MemoryStream();
        output.WriteULong(ulong.MaxValue);
        output.WriteULong(ulong.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadULong();
        Assert.Equal(ulong.MaxValue, result);
        result = input.ReadULong();
        Assert.Equal(ulong.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteUInt64Async()
    {
        using var output = new MemoryStream();
        await output.WriteULongAsync(ulong.MaxValue);
        await output.WriteULongAsync(ulong.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadULongAsync();
        Assert.Equal(ulong.MaxValue, result);
        result = await input.ReadULongAsync();
        Assert.Equal(ulong.MinValue, result);
    }
}