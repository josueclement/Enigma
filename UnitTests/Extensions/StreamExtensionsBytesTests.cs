using System.IO;
using System.Threading.Tasks;
using Enigma.Extensions;

namespace UnitTests.Extensions;

public class StreamExtensionsBytesTests
{
    [Fact]
    public void ReadWriteByte()
    {
        using var output = new MemoryStream();
        output.WriteByte(byte.MaxValue);
        output.WriteByte(byte.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadByte();
        Assert.Equal(byte.MaxValue, result);
        result = input.ReadByte();
        Assert.Equal(byte.MinValue, result);
    }
    
    [Fact]
    public async Task ReadWriteByteAsync()
    {
        using var output = new MemoryStream();
        await output.WriteByteAsync(byte.MaxValue);
        await output.WriteByteAsync(byte.MinValue);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadByteAsync();
        Assert.Equal(byte.MaxValue, result);
        result = await input.ReadByteAsync();
        Assert.Equal(byte.MinValue, result);
    }
    
    [Fact]
    public void ReadWriteBytes()
    {
        using var output = new MemoryStream();
        output.WriteBytes([0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = input.ReadBytes(4);
        Assert.Equal([0, 1, 254, 255], result);
    }
    
    [Fact]
    public async Task ReadWriteBytesAsync()
    {
        using var output = new MemoryStream();
        await output.WriteBytesAsync([0, 1, 254, 255]);
        
        using var input = new MemoryStream(output.ToArray());
        
        var result = await input.ReadBytesAsync(4);
        Assert.Equal([0, 1, 254, 255], result);
    }
}