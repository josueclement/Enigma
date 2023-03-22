using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace Enigma.PQC
{
    public static class Kyber
    {
        public static void GenerateKeyPair(out AsymmetricKeyParameter publicKey, out KyberPrivateKeyParameters privateKey, KyberParameters? parameters = null)
        {
            parameters ??= KyberParameters.kyber1024_aes;

            SecureRandom random = new SecureRandom();
            KyberKeyGenerationParameters keyGenParameters = new KyberKeyGenerationParameters(random, parameters);

            KyberKeyPairGenerator kyberKeyPairGenerator = new KyberKeyPairGenerator();
            kyberKeyPairGenerator.Init(keyGenParameters);

            AsymmetricCipherKeyPair keyPair = kyberKeyPairGenerator.GenerateKeyPair();
            publicKey = keyPair.Public;
            privateKey = (KyberPrivateKeyParameters)keyPair.Private;
        }

        public static void Generate(AsymmetricKeyParameter publicKey, out byte[] clearKey, out byte[] cipherKey)
        {
            KyberKemGenerator bobKyberKemGenerator = new KyberKemGenerator(new SecureRandom());
            ISecretWithEncapsulation encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(publicKey);
            clearKey = encapsulatedSecret.GetSecret();
            cipherKey = encapsulatedSecret.GetEncapsulation();
        }

        public static byte[] Extract(KyberPrivateKeyParameters privateKey, byte[] cipherKey)
        {
            KyberKemExtractor aliceKemExtractor = new KyberKemExtractor(privateKey);
            return aliceKemExtractor.ExtractSecret(cipherKey);
        }
    }
}
