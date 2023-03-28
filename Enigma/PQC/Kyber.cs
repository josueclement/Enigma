using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using System.IO;

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

        #region Save / Load PEM files

        /// <summary>
        /// Load public key from PEM
        /// </summary>
        /// <param name="input">Input stream</param>
        public static KyberPublicKeyParameters LoadPublicKeyFromPEM(Stream input)
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// Load private key from PEM
        /// </summary>
        /// <param name="input">Input stream</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input)
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// Load private key from PEM secured with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="password">Password</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input, string password)
        {
            throw new System.NotImplementedException();
        }

        /// <summary>
        /// Save public key to PEM
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="output">Output stream</param>
        public static void SavePublicKeyToPEM(KyberPublicKeyParameters publicKey, Stream output)
        {
            // !! save publicKey.Parameters infos
            // - Name : byte (to identify the type: 0x01=kyber512, 0x02=kyber768, etc..)
            // - K: 2/3/4 as byte too
            // - sessionKeySize: 128/192/256 as byte too
            // - usingAes: true/false as byte too

        }

        /// <summary>
        /// Save private key to PEM
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="output">Output stream</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, Stream output)
        {

        }

        /// <summary>
        /// Save private key to PEM secured with a password
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, Stream output, string password)
        {
            // !! in addition to the parameters info, write the salt 
        }

        #endregion
    }
}
