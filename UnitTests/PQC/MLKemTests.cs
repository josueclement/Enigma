using Enigma.PQC;
using Enigma.Utils;
using System.IO;
using System.Threading.Tasks;

namespace UnitTests.PQC;

// ReSharper disable once InconsistentNaming
public class MLKemTests
{
    [Fact]
    public async Task CheckGoodKey()
    {
        var service = new MLKemServiceFactory().CreateKem1024();
        
        var privateKeyInput = new FileStream(@"PQC\kem1024_A_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyInput, "test1234");
        
        var encapsulation = await File.ReadAllBytesAsync(@"PQC\encapsulation.bin");
        var secret = await File.ReadAllBytesAsync(@"PQC\secret.bin");

        var generatedKey = service.Decapsulate(encapsulation, privateKey);
        
        Assert.Equal(secret, generatedKey);
    }
    
    [Fact]
    public async Task CheckBadKey()
    {
        var service = new MLKemServiceFactory().CreateKem1024();
        
        var privateKeyInput = new FileStream(@"PQC\kem1024_B_private.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyInput, "test1234");
        
        var encapsulation = await File.ReadAllBytesAsync(@"PQC\encapsulation.bin");
        var secret = await File.ReadAllBytesAsync(@"PQC\secret.bin");

        var generatedKey = service.Decapsulate(encapsulation, privateKey);
        
        Assert.NotEqual(secret, generatedKey);
    }
}