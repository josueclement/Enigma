using System.IO;
using System.Security.Cryptography;
using System.Text;
using Enigma;
using Enigma.PublicKey;

namespace UnitTests.PublicKey;

public class RsaServiceTests
{
    [Fact]
    public void LoadPublicKey()
    {
        var srvc = new RsaService();

        using var input = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var key = srvc.LoadKey(input);

        Assert.NotNull(key);
    }

    [Fact]
    public void LoadPrivateKey()
    {
        var srvc = new RsaService();
        
        using var input = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var key = srvc.LoadPrivateKey(input, "test1234");
        
        Assert.NotNull(key);
    }

    [Fact]
    public void SignVerify()
    {
        var srvc = new RsaService();
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = srvc.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = srvc.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var signature = srvc.Sign(data, privateKey);
        var result = srvc.Verify(data, signature, publicKey);
        Assert.True(result);
    }

    [Fact]
    public void SignVerifyBadMessage()
    {
        var srvc = new RsaService();
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = srvc.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = srvc.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var otherData = Encoding.UTF8.GetBytes("This is not gonna work !");
        var signature = srvc.Sign(data, privateKey);
        var result = srvc.Verify(otherData, signature, publicKey);
        Assert.False(result);
    }
}