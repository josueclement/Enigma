using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;

namespace Enigma.PQC
{
    /// <summary>
    /// Dilithium helper class for key pair generation, sign and verify
    /// </summary>
    public static class Dilithium
    {
        /// <summary>
        /// Generate key pair
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="privateKey">Private key</param>
        /// <param name="parameters">Parameters</param>
        public static void GenerateKeyPair(out DilithiumPublicKeyParameters publicKey, out DilithiumPrivateKeyParameters privateKey, DilithiumParameters? parameters = null)
        {
            parameters ??= DilithiumParameters.Dilithium5;
            DilithiumKeyGenerationParameters keyGenParameters = new DilithiumKeyGenerationParameters(new SecureRandom(), parameters);
            DilithiumKeyPairGenerator dilithiumKeyPairGenerator = new DilithiumKeyPairGenerator();
            dilithiumKeyPairGenerator.Init(keyGenParameters);
            AsymmetricCipherKeyPair keyPair = dilithiumKeyPairGenerator.GenerateKeyPair();
            publicKey = (DilithiumPublicKeyParameters)keyPair.Public;
            privateKey = (DilithiumPrivateKeyParameters)keyPair.Private;
        }

        /// <summary>
        /// Sign data
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <param name="privateKey">Private key</param>
        public static byte[] Sign(byte[] data, DilithiumPrivateKeyParameters privateKey)
        {
            DilithiumSigner signer = new DilithiumSigner();
            signer.Init(true, privateKey);
            return signer.GenerateSignature(data);
        }

        /// <summary>
        /// Signature to verify
        /// </summary>
        /// <param name="data">Original data</param>
        /// <param name="signature">Signature</param>
        /// <param name="publicKey">Public key</param>
        public static bool Verify(byte[] data, byte[] signature, DilithiumPublicKeyParameters publicKey)
        {
            DilithiumSigner signer = new DilithiumSigner();
            signer.Init(false, publicKey);
            return signer.VerifySignature(data, signature);
        }
    }
}
