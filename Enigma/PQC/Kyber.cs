using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace Enigma.PQC
{
    /// <summary>
    /// Kyber helper class for key pair generation and sym key generation/extraction
    /// </summary>
    public static class Kyber
    {
        /// <summary>
        /// Generate key pair
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="privateKey">Private key</param>
        /// <param name="parameters">Parameters</param>
        public static void GenerateKeyPair(out KyberPublicKeyParameters publicKey, out KyberPrivateKeyParameters privateKey, KyberParameters? parameters = null)
        {
            parameters ??= KyberParameters.kyber1024_aes;

            SecureRandom random = new SecureRandom();
            KyberKeyGenerationParameters keyGenParameters = new KyberKeyGenerationParameters(random, parameters);
            KyberKeyPairGenerator kyberKeyPairGenerator = new KyberKeyPairGenerator();
            kyberKeyPairGenerator.Init(keyGenParameters);
            AsymmetricCipherKeyPair keyPair = kyberKeyPairGenerator.GenerateKeyPair();
            publicKey = (KyberPublicKeyParameters)keyPair.Public;
            privateKey = (KyberPrivateKeyParameters)keyPair.Private;
        }

        /// <summary>
        /// Generate a new sym key
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="clearKey">Clear sym key</param>
        /// <param name="encryptedKey">Encrypted sym key</param>
        public static void Generate(AsymmetricKeyParameter publicKey, out byte[] clearKey, out byte[] encryptedKey)
        {
            KyberKemGenerator bobKyberKemGenerator = new KyberKemGenerator(new SecureRandom());
            ISecretWithEncapsulation encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(publicKey);
            clearKey = encapsulatedSecret.GetSecret();
            encryptedKey = encapsulatedSecret.GetEncapsulation();
        }

        /// <summary>
        /// Extract a private key
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="encryptedKey">Encrypted sym key</param>
        /// <returns></returns>
        public static byte[] Extract(KyberPrivateKeyParameters privateKey, byte[] encryptedKey)
        {
            KyberKemExtractor aliceKemExtractor = new KyberKemExtractor(privateKey);
            return aliceKemExtractor.ExtractSecret(encryptedKey);
        }
    }
}
