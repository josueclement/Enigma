using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.PublicKey;

public class RsaService
{
    public AsymmetricCipherKeyPair GenerateKeyPair(int keySize = 4096)
    {
        var generator = new RsaKeyPairGenerator(); //IAsymmetricCipherKeyPairGenerator
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    // public byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
    // {
    //     // var engine = new RsaEngine();
    //     // engine.Init(true, publicKey);
    //     // CipherUtilities.GetCipher()
    //     // engine.pro
    //     var cipher = new Pkcs1Encoding(new RsaEngine());
    //     var parameters = new ParametersWithRandom(publicKey, new SecureRandom());
    //     cipher.Init(true, parameters);
    //     cipher.ProcessBlock()
    // }
}