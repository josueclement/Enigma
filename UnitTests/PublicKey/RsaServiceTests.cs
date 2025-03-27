using Enigma.Extensions;
using Enigma.PublicKey;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System.IO;
using System.Text;

namespace UnitTests.PublicKey;

public class RsaServiceTests
{
    IAsymmetricBlockCipher GetCipher() => new Pkcs1Encoding(new RsaEngine());
    IAsymmetricCipherKeyPairGenerator GetKeyPairGenerator() => new RsaKeyPairGenerator();
    ISigner GetSigner() => SignerUtilities.GetSigner("SHA256withRSA");
    
    [Fact]
    public void LoadPublicKey()
    {
        var service = new PublicKeyService(GetCipher, GetKeyPairGenerator, GetSigner);

        using var input = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var key = service.LoadKey(input);

        Assert.NotNull(key);
    }

    [Fact]
    public void LoadPrivateKey()
    {
        var service = new PublicKeyService(GetCipher, GetKeyPairGenerator, GetSigner);
        
        using var input = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var key = service.LoadPrivateKey(input, "test1234");
        
        Assert.NotNull(key);
    }

    [Fact]
    public void SignVerify()
    {
        var service = new PublicKeyService(GetCipher, GetKeyPairGenerator, GetSigner);
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = service.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = service.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var signature = service.Sign(data, privateKey);
        var result = service.Verify(data, signature, publicKey);
        Assert.True(result);
    }

    [Fact]
    public void SignVerifyBadMessage()
    {
        var service = new PublicKeyService(GetCipher, GetKeyPairGenerator, GetSigner);
        
        using var inputPrivate = new FileStream(@"PublicKey\pk_key1.pem", FileMode.Open, FileAccess.Read);
        var privateKey = service.LoadPrivateKey(inputPrivate, "test1234");
        using var inputPublic = new FileStream(@"PublicKey\pub_key1.pem", FileMode.Open, FileAccess.Read);
        var publicKey = service.LoadKey(inputPublic);
        
        var data = Encoding.UTF8.GetBytes("This message will be signed and verified");
        var otherData = Encoding.UTF8.GetBytes("This is not gonna work !");
        var signature = service.Sign(data, privateKey);
        var result = service.Verify(otherData, signature, publicKey);
        Assert.False(result);
    }
}