using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Enigma.PubKey
{
    /// <summary>
    /// RSA helper class for key generation, data encrypt/decrypt, sign/verify and key load/save
    /// </summary>
    public static class RSA
    {
        /// <summary>
        /// Generate a new RSA key pair
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        public static RSACryptoServiceProvider GenerateKeyPair(int keySize = 4096)
            => new RSACryptoServiceProvider(keySize);

        #region Encrypt / Decrypt data

        /// <summary>
        /// Encrypt data using RSACryptoServiceProvider
        /// </summary>
        /// <param name="publicKey">RSA public key</param>
        /// <param name="data">Data to encrypt</param>
        public static byte[] Encrypt(RSACryptoServiceProvider publicKey, byte[] data)
            => publicKey.Encrypt(data, true);

        /// <summary>
        /// Decrypt data using RSACryptoServiceProvider
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <param name="encrypted">Data to decrypt</param>
        public static byte[] Decrypt(RSACryptoServiceProvider privateKey, byte[] encrypted)
            => privateKey.Decrypt(encrypted, true);

        #endregion
        
        #region Sign / Verify data

        /// <summary>
        /// Sign data with a RSA private key
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <param name="data">Data to sign</param>
        /// <param name="hashAlgorithmName">Hash algorithm name (will default to <see cref="HashAlgorithmName.SHA512"/> if null</param>
        /// <param name="signaturePadding">Signature padding (will default to <see cref="RSASignaturePadding.Pkcs1"/> if null</param>
        public static byte[] Sign(RSACryptoServiceProvider privateKey, byte[] data, HashAlgorithmName? hashAlgorithmName = null, RSASignaturePadding? signaturePadding = null)
        {
            var algorithmNameInternal = hashAlgorithmName ?? HashAlgorithmName.SHA512;
            var signaturePaddingInternal = signaturePadding ?? RSASignaturePadding.Pkcs1;
            return privateKey.SignData(data, algorithmNameInternal, signaturePaddingInternal);
        }

        /// <summary>
        /// Verifies signed data with a RSA public key
        /// </summary>
        /// <param name="publicKey">RSA public key</param>
        /// <param name="data">Original data</param>
        /// <param name="signature">Signature data</param>
        /// <param name="hashAlgorithmName">Hash algorithm name (will default to <see cref="HashAlgorithmName.SHA512"/> if null</param>
        /// <param name="signaturePadding">Signature padding (will default to <see cref="RSASignaturePadding.Pkcs1"/> if null</param>
        public static bool Verify(RSACryptoServiceProvider publicKey, byte[] data, byte[] signature, HashAlgorithmName? hashAlgorithmName = null, RSASignaturePadding? signaturePadding = null)
        {
            var algorithmNameInternal = hashAlgorithmName ?? HashAlgorithmName.SHA512;
            var signaturePaddingInternal = signaturePadding ?? RSASignaturePadding.Pkcs1;

            return publicKey.VerifyData(data, signature, algorithmNameInternal, signaturePaddingInternal);
        }
        
        #endregion

        #region Save / Load PEM files

        /// <summary>
        /// Load a PEM from stream 
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="password">Password</param>
        public static RSACryptoServiceProvider LoadFromPEM(Stream input, string? password = null)
        {
            using (StreamReader sr = new StreamReader(input, Encoding.Default))
            {
                PemReader pemReader;
                if (!string.IsNullOrEmpty(password))
                    pemReader = new PemReader(sr, new PasswordFinder(password));
                else
                    pemReader = new PemReader(sr);

                RSAParameters parameters;
                object obj = pemReader.ReadObject();

                if (obj == null)
                    throw new PemException("PemReader.ReadObject() returned null");

                Type objType = obj.GetType();

                if (objType == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair ackp = (AsymmetricCipherKeyPair)obj;
                    parameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)ackp.Private);
                }
                else if (objType == typeof(RsaPrivateCrtKeyParameters))
                    parameters = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)obj);
                else if (objType == typeof(RsaKeyParameters))
                    parameters = DotNetUtilities.ToRSAParameters((RsaKeyParameters)obj);
                else
                    throw new PemException($"Cannot handle type '{objType}' returned by PemReader.ReadObject()");

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(parameters);
                return rsa;
            }
        }

        /// <summary>
        /// Load a PEM file
        /// </summary>
        /// <param name="filePath">PEM file path</param>
        /// <param name="password">Password</param>
        public static RSACryptoServiceProvider LoadFromPEM(string filePath, string? password = null)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return LoadFromPEM(fs, password);
            }
        }

        /// <summary>
        /// Save a public RSA key to a PEM stream
        /// </summary>
        /// <param name="publicKey">RSA public key</param>
        /// <param name="output">Output stream</param>
        public static void SavePublicKeyToPEM(RSACryptoServiceProvider publicKey, Stream output)
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                RsaKeyParameters rkp = DotNetUtilities.GetRsaPublicKey(publicKey);
                pemWriter.WriteObject(rkp);
            }
        }

        /// <summary>
        /// Save a public RSA key to a PEM file
        /// </summary>
        /// <param name="publicKey">RSA public key</param>
        /// <param name="outputFile">PEM output file</param>
        public static void SavePublicKeyToPEM(RSACryptoServiceProvider publicKey, string outputFile)
        {
            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePublicKeyToPEM(publicKey, fs);
            }
        }

        /// <summary>
        /// Save an encrypted private RSA key to a PEM stream
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="algorithm">Algorithm for PEM encryption</param>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider privateKey, Stream output, string password, string algorithm = "AES-256-CBC")
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                AsymmetricCipherKeyPair ackp = DotNetUtilities.GetRsaKeyPair(privateKey);
                RsaPrivateCrtKeyParameters privKey = (RsaPrivateCrtKeyParameters)ackp.Private;
                pemWriter.WriteObject(privKey, algorithm, password.ToCharArray(), new SecureRandom());
            }
        }

        /// <summary>
        /// Save an encrypted RSA key to a PEM file
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <param name="outputFile">PEM output file</param>
        /// <param name="password">Password</param>
        /// <param name="algorithm">Algorithm</param>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider privateKey, string outputFile, string password, string algorithm = "AES-256-CBC")
        {
            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(privateKey, fs, password, algorithm);
            }
        }

        /// <summary>
        /// Save a private RSA key to a PEM file
        /// </summary>
        /// <param name="privateKey">RSA private key</param>
        /// <param name="output">Output stream</param>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider privateKey, Stream output)
        {
            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                AsymmetricCipherKeyPair ackp = DotNetUtilities.GetRsaKeyPair(privateKey);
                RsaPrivateCrtKeyParameters privKey = (RsaPrivateCrtKeyParameters)ackp.Private;
                pemWriter.WriteObject(privKey);
            }
        }

        /// <summary>
        /// Save a private RSA key to a PEM file
        /// </summary>
        /// <param name="privateKey"></param>
        /// <param name="outputFile"></param>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider privateKey, string outputFile)
        {
            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(privateKey, fs);
            }
        }

        #endregion

        #region Save / Load Win KeyStore

        /// <summary>
        /// Save a RSA key in the Windows KeyStore
        /// </summary>
        /// <param name="key">RSA key</param>
        /// <param name="containerName">Container name</param>
        /// <param name="csppf">CspProviderFlags</param>
        public static void SaveInWinKeyStore(RSACryptoServiceProvider key, string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = containerName;
            cp.Flags = csppf;

            using (RSACryptoServiceProvider winKSkey = new RSACryptoServiceProvider(cp))
            {
                winKSkey.FromXmlString(key.ToXmlString(true));
            }
        }

        /// <summary>
        /// Load a RSA key from the Windows KeyStore 
        /// </summary>
        /// <param name="containerName">Container name</param>
        /// <param name="csppf">CspProviderFlags</param>
        public static RSACryptoServiceProvider LoadFromWinKeyStore(string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = containerName;
            cp.Flags = csppf;

            return new RSACryptoServiceProvider(cp);
        }

        /// <summary>
        /// Delete a RSA key from the Windows KeyStore
        /// </summary>
        /// <param name="containerName">Container name</param>
        /// <param name="csppf">CspProviderFlags</param>
        public static void DeleteFromWinKeyStore(string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = containerName;
            cp.Flags = csppf;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp))
            {
                rsa.PersistKeyInCsp = false;
                rsa.Clear();
            }
        }

        #endregion

        /// <summary>
        /// Password finder helper used by PemReader
        /// </summary>
        class PasswordFinder : IPasswordFinder
        {
            private string? _password;

            public PasswordFinder(string? password)
            {
                _password = password;
            }

            /// <summary>
            /// Get password stored
            /// </summary>
            /// <returns>Password</returns>
            public char[]? GetPassword()
            {
                return _password?.ToCharArray();
            }
        }
    }
}
