using Enigma.IO;
using Enigma.KDF;
using Enigma.Padding;
using Enigma.Random;
using Enigma.SymKey;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Enigma.PQC
{
    internal readonly struct KyberComponentsSizes
    {
        public KyberComponentsSizes(int t, int rho, int hpk, int s, int nonce)
        {
            T = t;
            Rho = rho;
            Hpk = hpk;
            S = s;
            Nonce = nonce;
        }

        public int T { get; }
        public int Rho { get; }
        public int Hpk { get; }
        public int S { get; }
        public int Nonce { get; }

        public static KyberComponentsSizes GetComponentsSizes(string name)
        {
            switch (name)
            {
                case Kyber.KYBER512_NAME:
                case Kyber.KYBER512_AES_NAME:
                    return new KyberComponentsSizes(768, 32, 32, 768, 32);
                case Kyber.KYBER768_NAME:
                case Kyber.KYBER768_AES_NAME:
                    return new KyberComponentsSizes(1152, 32, 32, 1152, 32);
                case Kyber.KYBER1024_NAME:
                case Kyber.KYBER1024_AES_NAME:
                    return new KyberComponentsSizes(1536, 32, 32, 1536, 32);
                default:
                    throw new InvalidOperationException();
            }
        }
    }

    /// <summary>
    /// Kyber helper class for key pair generation and sym key generation/extraction
    /// </summary>
    public static class Kyber
    {
        /// <summary>
        /// <see cref="KyberParameters.kyber512"/> name
        /// </summary>
        public const string KYBER512_NAME = "kyber512";
        /// <summary>
        /// <see cref="KyberParameters.kyber512_aes"/> name
        /// </summary>
        public const string KYBER512_AES_NAME = "kyber512-aes";
        /// <summary>
        /// <see cref="KyberParameters.kyber768"/> name
        /// </summary>
        public const string KYBER768_NAME = "kyber768";
        /// <summary>
        /// <see cref="KyberParameters.kyber768_aes"/> name
        /// </summary>
        public const string KYBER768_AES_NAME = "kyber768-aes";
        /// <summary>
        /// <see cref="KyberParameters.kyber1024"/> name
        /// </summary>
        public const string KYBER1024_NAME = "kyber1024";
        /// <summary>
        /// <see cref="KyberParameters.kyber1024_aes"/> name
        /// </summary>
        public const string KYBER1024_AES_NAME = "kyber1024-aes";

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
            PemContent pem = Pem.Read(input);
            string name = pem.Header.FirstOrDefault(x => x.Name == "Name")?.Value ?? throw new InvalidOperationException();
            byte[] data = pem.Data ?? throw new InvalidOperationException();

            KyberParameters parameters = GetParameters(name);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(name);
            byte[] t = new byte[sizes.T];
            byte[] rho = new byte[sizes.Rho];

            int index = 0;
            Array.Copy(data, index, t, 0, sizes.T);
            index += sizes.T;
            Array.Copy(data, index, rho, 0, sizes.Rho);

            return new KyberPublicKeyParameters(parameters, t, rho);
        }

        /// <summary>
        /// Load private key from PEM
        /// </summary>
        /// <param name="input">Input stream</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input)
        {
            PemContent pem = Pem.Read(input);
            string name = pem.Header.FirstOrDefault(x => x.Name == "Name")?.Value ?? throw new InvalidOperationException();
            byte[] data = pem.Data ?? throw new InvalidOperationException();

            KyberParameters parameters = GetParameters(name);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(name);

            byte[] s = new byte[sizes.S];
            byte[] t = new byte[sizes.T];
            byte[] rho = new byte[sizes.Rho];
            byte[] hpk = new byte[sizes.Hpk];
            byte[] nonce = new byte[sizes.Nonce];

            int index = 0;
            Array.Copy(data, index, s, 0, sizes.S);
            index += sizes.S;
            Array.Copy(data, index, t, 0, sizes.T);
            index += sizes.T;
            Array.Copy(data, index, rho, 0, sizes.Rho);
            index += sizes.Rho;
            Array.Copy(data, index, hpk, 0, sizes.Hpk);
            index += sizes.Hpk;
            Array.Copy(data, index, nonce, 0, sizes.Nonce);

            return new KyberPrivateKeyParameters(parameters, s, hpk, nonce, t, rho);
        }

        /// <summary>
        /// Load private key from PEM secured with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="password">Password</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input, string password)
        {
            PemContent pem = Pem.Read(input);
            string name = pem.Header.FirstOrDefault(x => x.Name == "Name")?.Value ?? throw new InvalidOperationException();
            string saltStr = pem.Header.FirstOrDefault(x => x.Name == "Salt")?.Value ?? throw new InvalidOperationException();
            string ivStr = pem.Header.FirstOrDefault(x => x.Name == "IV")?.Value ?? throw new InvalidOperationException();
            byte[] enc = pem.Data ?? throw new InvalidOperationException();

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, Hex.Decode(saltStr), 600_000);
            byte[] iv = Hex.Decode(ivStr);
            byte[] dec = AES.DecryptCBC(enc, key, iv);

            byte[] data = new Pkcs7Padding().Unpad(dec, AES.BLOCK_SIZE);

            KyberParameters parameters = GetParameters(name);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(name);

            byte[] s = new byte[sizes.S];
            byte[] t = new byte[sizes.T];
            byte[] rho = new byte[sizes.Rho];
            byte[] hpk = new byte[sizes.Hpk];
            byte[] nonce = new byte[sizes.Nonce];

            int index = 0;
            Array.Copy(data, index, s, 0, sizes.S);
            index += sizes.S;
            Array.Copy(data, index, t, 0, sizes.T);
            index += sizes.T;
            Array.Copy(data, index, rho, 0, sizes.Rho);
            index += sizes.Rho;
            Array.Copy(data, index, hpk, 0, sizes.Hpk);
            index += sizes.Hpk;
            Array.Copy(data, index, nonce, 0, sizes.Nonce);

            return new KyberPrivateKeyParameters(parameters, s, hpk, nonce, t, rho);
        }

        /// <summary>
        /// Save public key to PEM
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="name">Parameters name</param>
        /// <param name="output">Output stream</param>
        public static void SavePublicKeyToPEM(KyberPublicKeyParameters publicKey, string name, Stream output)
        {
            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Name",
                    Value = name
                }
            };

            byte[] data = publicKey.GetEncoded();
            Pem.Write("KYBER PUBLIC KEY", header, data, output);
        }

        /// <summary>
        /// Save private key to PEM
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="name">Parameters name</param>
        /// <param name="output">Output stream</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string name, Stream output)
        {
            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Name",
                    Value = name
                }
            };

            byte[] data = privateKey.GetEncoded();
            Pem.Write("KYBER PRIVATE KEY", header, data, output);
            Array.Clear(data, 0, data.Length);
        }

        /// <summary>
        /// Save private key to PEM secured with a password
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="name">Parameters name</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string name, Stream output, string password)
        {
            byte[] salt = RandomHelper.GenerateBytes(16);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Name",
                    Value = name
                },
                new PemHeaderItem
                {
                    Name = "Salt",
                    Value = Hex.Encode(salt).ToUpper()
                },
                new PemHeaderItem
                {
                    Name = "IV",
                    Value = Hex.Encode(iv).ToUpper()
                }
            };

            byte[] data = privateKey.GetEncoded();
            byte[] padded = new Pkcs7Padding().Pad(data, AES.BLOCK_SIZE);
            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 600_000);
            byte[] enc = AES.EncryptCBC(padded, key, iv);
            Array.Clear(key, 0, key.Length);
            Array.Clear(data, 0, data.Length);
            Array.Clear(padded, 0, padded.Length);

            Pem.Write("KYBER ENCRYPTED PRIVATE KEY", header, enc, output);
        }

        #endregion

        #region Helpers

        private static KyberParameters GetParameters(string name)
        {
            switch (name)
            {
                case KYBER512_NAME:
                    return KyberParameters.kyber512;
                case KYBER512_AES_NAME:
                    return KyberParameters.kyber512_aes;
                case KYBER768_NAME:
                    return KyberParameters.kyber768;
                case KYBER768_AES_NAME:
                    return KyberParameters.kyber768_aes;
                case KYBER1024_NAME:
                    return KyberParameters.kyber1024;
                case KYBER1024_AES_NAME:
                    return KyberParameters.kyber1024_aes;
                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion
    }
}
