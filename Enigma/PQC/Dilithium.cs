using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Enigma.PQC
{
    public static class Dilithium
    {
        public static void GenerateKeyPair(out DilithiumPublicKeyParameters publicKey, out DilithiumPrivateKeyParameters privateKey, DilithiumParameters parameters = null)
        {
            parameters ??= DilithiumParameters.Dilithium5;
            DilithiumKeyGenerationParameters keyGenParameters = new DilithiumKeyGenerationParameters(new SecureRandom(), parameters);

            DilithiumKeyPairGenerator dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
            dilithiumKeyPairGenerator.Init(keyGenParameters);
            AsymmetricCipherKeyPair keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
            publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
            privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
        }

        public static byte[] Sign(byte[] data, DilithiumPrivateKeyParameters privateKey)
        {
            DilithiumSigner signer = new DilithiumSigner();
            signer.Init(true, privateKey);
            return signer.GenerateSignature(data);
        }

        public static bool Verify(byte[] data, byte[] signature, DilithiumPublicKeyParameters publicKey)
        {
            DilithiumSigner signer = new DilithiumSigner();
            signer.Init(false, publicKey);
            return signer.VerifySignature(data, signature);
        }
    }
}
