using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Enigma.PublicKey;

/// <summary>
/// RSA service
/// </summary>
public class RsaService : PublicKeyServiceBase
{
    /// <inheritdoc />
    protected override IAsymmetricCipherKeyPairGenerator BuildKeyPairGenerator(int keySize)
    {
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator;
    }

    /// <inheritdoc />
    protected override IAsymmetricBlockCipher BuildCipher(bool forEncryption, AsymmetricKeyParameter key)
    {
        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption, key);
        return cipher;
    }

    /// <inheritdoc />
    protected override ISigner BuildSigner(bool forSigning, AsymmetricKeyParameter key)
    {
        var signer = SignerUtilities.GetSigner("SHA256withRSA");
        signer.Init(forSigning, key);
        return signer;
    }

    // public void SaveKey(AsymmetricKeyParameter key, Stream output)
    // {
    //     using var writer = new StreamWriter(output, Encoding.UTF8);
    //     var pemWriter = new PemWriter(writer);
    //     pemWriter.WriteObject(key);
    // }
    //
    // public void SavePrivateKey(AsymmetricKeyParameter privateKey, Stream output, string password, string algorithm = "AES-256-CBC")
    // {
    //     using var writer = new StreamWriter(output, Encoding.UTF8);
    //     var pemWriter = new PemWriter(writer);
    //     pemWriter.WriteObject(privateKey, algorithm, password.ToCharArray(), new SecureRandom());
    // }
    //
    // public AsymmetricKeyParameter LoadKey(Stream input)
    // {
    //     using var reader = new StreamReader(input, Encoding.UTF8);
    //     var pemReader = new PemReader(reader);
    //     object obj = pemReader.ReadObject();
    //
    //     if (obj is AsymmetricCipherKeyPair ackp)
    //     {
    //         return ackp;
    //     }
    //
    //     if (obj is RsaPrivateCrtKeyParameters rpckp)
    //     {
    //         return rpckp;
    //     }
    //
    //     if (obj is RsaKeyParameters rkp)
    //     {
    //         return rkp;
    //     }
    // }
}