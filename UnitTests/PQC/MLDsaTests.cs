using Enigma.Cryptography.PQC;
using Enigma.Cryptography.Utils;
using System.IO;
using System.Threading.Tasks;

namespace UnitTests.PQC;

// ReSharper disable once InconsistentNaming
public class MLDsaTests
{
    [Fact]
    public async Task VerifyGoodSignature()
    {
        var service = new MLDsaServiceFactory().CreateDsa87Service();
        
        var publicKeyInput = new FileStream(@"PQC\dsa87_A_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyInput);
        
        var messageData = await File.ReadAllBytesAsync(@"PQC\message.txt");
        var signature = await File.ReadAllBytesAsync(@"PQC\signature.bin");
        var isValid = service.Verify(messageData, signature, publicKey);
        
        Assert.True(isValid);
    }
    
    [Fact]
    public async Task VerifyBadSignature()
    {
        var service = new MLDsaServiceFactory().CreateDsa87Service();
        
        var publicKeyInput = new FileStream(@"PQC\dsa87_B_public.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(publicKeyInput);
        
        var messageData = await File.ReadAllBytesAsync(@"PQC\message.txt");
        var signature = await File.ReadAllBytesAsync(@"PQC\signature.bin");
        var isValid = service.Verify(messageData, signature, publicKey);
        
        Assert.False(isValid);
    }
}