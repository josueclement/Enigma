using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using System.IO;
using System.Text;

namespace UnitTests.PublicKey;

public class RsaServiceTests
{
    [Fact]
    public void LoadPublicKey()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();

        using var input = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var key = PemUtils.LoadKey(input);

        Assert.NotNull(key);
    }

    [Fact]
    public void LoadPrivateKey()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        
        using var input = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var key = PemUtils.LoadPrivateKey(input, "test1234");
        
        Assert.NotNull(key);
    }

    [Fact]
    public void SignVerify()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var signature = service.Sign(data, privateKey);
        var result = service.Verify(data, signature, publicKey);
        Assert.True(result);
    }

    [Fact]
    public void SignVerifyBadMessage()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = PemUtils.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var otherData = Encoding.UTF8.GetBytes("This is not gonna work !");
        var signature = service.Sign(data, privateKey);
        var result = service.Verify(otherData, signature, publicKey);
        Assert.False(result);
    }
}