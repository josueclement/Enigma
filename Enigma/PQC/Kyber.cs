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

        public static KyberComponentsSizes GetComponentsSizes(string type)
        {
            switch (type)
            {
                case Kyber.KYBER512:
                    return new KyberComponentsSizes(768, 32, 32, 768, 32);
                case Kyber.KYBER768:
                    return new KyberComponentsSizes(1152, 32, 32, 1152, 32);
                case Kyber.KYBER1024:
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
        public const string KYBER512 = "kyber512";
        /// <summary>
        /// <see cref="KyberParameters.kyber768"/> name
        /// </summary>
        public const string KYBER768 = "kyber768";
        /// <summary>
        /// <see cref="KyberParameters.kyber1024"/> name
        /// </summary>
        public const string KYBER1024 = "kyber1024";

        /// <summary>
        /// Generate key pair
        /// </summary>
        /// <param name="type">Parameters type</param>
        /// <param name="publicKey">Public key</param>
        /// <param name="privateKey">Private key</param>
        public static void GenerateKeyPair(string type, out KyberPublicKeyParameters publicKey, out KyberPrivateKeyParameters privateKey)
        {
            KyberParameters parameters;

            switch (type)
            {
                case KYBER512:
                    parameters = KyberParameters.kyber512;
                    break;
                case KYBER768:
                    parameters = KyberParameters.kyber768;
                    break;
                case KYBER1024:
                    parameters = KyberParameters.kyber1024;
                    break;
                default:
                    throw new InvalidOperationException();
            }

            KyberKeyGenerationParameters keyGenParameters = new KyberKeyGenerationParameters(new SecureRandom(), parameters);
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
            string type = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
            byte[] data = pem.Data ?? throw new InvalidOperationException();

            KyberParameters parameters = GetParameters(type);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(type);
            byte[] t = new byte[sizes.T];
            byte[] rho = new byte[sizes.Rho];

            int index = 0;
            Array.Copy(data, index, t, 0, sizes.T);
            index += sizes.T;
            Array.Copy(data, index, rho, 0, sizes.Rho);

            return new KyberPublicKeyParameters(parameters, t, rho);
        }

        /// <summary>
        /// Load public key from PEM file
        /// </summary>
        /// <param name="filePath">File path</param>
        public static KyberPublicKeyParameters LoadPublicKeyFromPEM(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return LoadPublicKeyFromPEM(fs);
            }
        }

        /// <summary>
        /// Load private key from PEM
        /// </summary>
        /// <param name="input">Input stream</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input)
        {
            PemContent pem = Pem.Read(input);
            string type = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
            byte[] data = pem.Data ?? throw new InvalidOperationException();

            KyberParameters parameters = GetParameters(type);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(type);

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
        /// Load private key from PEM file
        /// </summary>
        /// <param name="filePath">File path</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return LoadPrivateKeyFromPEM(fs);
            }
        }

        /// <summary>
        /// Load private key from PEM secured with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="password">Password</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(Stream input, string password)
        {
            PemContent pem = Pem.Read(input);
            string type = pem.Header.FirstOrDefault(x => x.Name == "Type")?.Value ?? throw new InvalidOperationException();
            string saltStr = pem.Header.FirstOrDefault(x => x.Name == "Salt")?.Value ?? throw new InvalidOperationException();
            string ivStr = pem.Header.FirstOrDefault(x => x.Name == "IV")?.Value ?? throw new InvalidOperationException();
            byte[] enc = pem.Data ?? throw new InvalidOperationException();

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, Hex.Decode(saltStr), 600_000);
            byte[] iv = Hex.Decode(ivStr);
            byte[] dec = AES.DecryptCBC(enc, key, iv);

            byte[] data = new Pkcs7Padding().Unpad(dec, AES.BLOCK_SIZE);

            KyberParameters parameters = GetParameters(type);
            KyberComponentsSizes sizes = KyberComponentsSizes.GetComponentsSizes(type);

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
        /// Load private key from PEM file secured with password
        /// </summary>
        /// <param name="filePath">File path</param>
        /// <param name="password">Password</param>
        public static KyberPrivateKeyParameters LoadPrivateKeyFromPEM(string filePath, string password)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return LoadPrivateKeyFromPEM(fs, password);
            }
        }

        /// <summary>
        /// Save public key to PEM
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="output">Output stream</param>
        public static void SavePublicKeyToPEM(KyberPublicKeyParameters publicKey, string type, Stream output)
        {
            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Type",
                    Value = type
                }
            };

            byte[] data = publicKey.GetEncoded();
            Pem.Write("KYBER PUBLIC KEY", header, data, output);
        }

        /// <summary>
        /// Save public key to PEM file
        /// </summary>
        /// <param name="publicKey">Public key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="filePath">File path</param>
        public static void SavePublicKeyToPEM(KyberPublicKeyParameters publicKey, string type, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                SavePublicKeyToPEM(publicKey, type, fs);
            }
        }

        /// <summary>
        /// Save private key to PEM
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="output">Output stream</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string type, Stream output)
        {
            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Type",
                    Value = type
                }
            };

            byte[] data = privateKey.GetEncoded();
            Pem.Write("KYBER PRIVATE KEY", header, data, output);
            Array.Clear(data, 0, data.Length);
        }

        /// <summary>
        /// Save private key to PEM file
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="filePath">File path</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string type, string filePath)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(privateKey, type, fs);
            }
        }

        /// <summary>
        /// Save private key to PEM secured with a password
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string type, Stream output, string password)
        {
            byte[] salt = RandomHelper.GenerateBytes(16);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            List<PemHeaderItem> header = new List<PemHeaderItem>
            {
                new PemHeaderItem
                {
                    Name = "Type",
                    Value = type
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

        /// <summary>
        /// Save private key to PEM file secured with a password
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="type">Parameters type</param>
        /// <param name="filePath">File path</param>
        /// <param name="password">Password</param>
        public static void SavePrivateKeyToPEM(KyberPrivateKeyParameters privateKey, string type, string filePath, string password)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(privateKey, type, fs, password);
            }
        }

        #endregion

        #region Helpers

        private static KyberParameters GetParameters(string type)
        {
            switch (type)
            {
                case KYBER512:
                    return KyberParameters.kyber512;
                case KYBER768:
                    return KyberParameters.kyber768;
                case KYBER1024:
                    return KyberParameters.kyber1024;
                default:
                    throw new InvalidOperationException();
            }
        }

        #endregion
    }
}
