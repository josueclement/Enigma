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
    /// RSA helper class for key generation, data encrypt/decrypt and key load/save
    /// </summary>
    public static class RSA
    {
        /// <summary>
        /// Generate a new RSA key pair
        /// </summary>
        /// <param name="keySize">Key size in bits</param>
        public static RSACryptoServiceProvider GenerateKeyPair(int keySize = 4096)
        {
            return new RSACryptoServiceProvider(keySize);
        }

        #region Encrypt / Decrypt data

        /// <summary>
        /// Encrypt data using RSACryptoServiceProvider
        /// </summary>
        /// <param name="rsa">RSA Key</param>
        /// <param name="data">Data to encrypt</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Encrypt(RSACryptoServiceProvider rsa, byte[] data)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            return rsa.Encrypt(data, true);
        }

        /// <summary>
        /// Decrypt data using RSACryptoServiceProvider
        /// </summary>
        /// <param name="rsa">RSA Key</param>
        /// <param name="encrypted">Data to decrypt</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Decrypt(RSACryptoServiceProvider rsa, byte[] encrypted)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (encrypted == null)
                throw new ArgumentNullException(nameof(encrypted));

            return rsa.Decrypt(encrypted, true);
        }

        #endregion

        #region Save / Load PEM files

        /// <summary>
        /// Load a PEM from stream 
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="password">Password</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static RSACryptoServiceProvider LoadFromPEM(Stream input, string? password = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

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
        /// <exception cref="ArgumentNullException"></exception>
        public static RSACryptoServiceProvider LoadFromPEM(string filePath, string? password = null)
        {
            if (filePath == null)
                throw new ArgumentNullException(nameof(filePath));

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return LoadFromPEM(fs, password);
            }
        }

        /// <summary>
        /// Save a public RSA key to a PEM stream
        /// </summary>
        /// <param name="rsa">Public key</param>
        /// <param name="output">Output stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePublicKeyToPEM(RSACryptoServiceProvider rsa, Stream output)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (output == null)
                throw new ArgumentNullException(nameof(output));

            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                RsaKeyParameters rkp = DotNetUtilities.GetRsaPublicKey(rsa);
                pemWriter.WriteObject(rkp);
            }
        }

        /// <summary>
        /// Save a public RSA key to a PEM file
        /// </summary>
        /// <param name="rsa">Public key</param>
        /// <param name="outputFile">PEM output file</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePublicKeyToPEM(RSACryptoServiceProvider rsa, string outputFile)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));

            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePublicKeyToPEM(rsa, fs);
            }
        }

        /// <summary>
        /// Save an encrypted private RSA key to a PEM stream
        /// </summary>
        /// <param name="rsa">Private key</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="algorithm">Algorithm for PEM encryption</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider rsa, Stream output, string password, string algorithm = "AES-256-CBC")
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                AsymmetricCipherKeyPair ackp = DotNetUtilities.GetRsaKeyPair(rsa);
                RsaPrivateCrtKeyParameters privKey = (RsaPrivateCrtKeyParameters)ackp.Private;
                pemWriter.WriteObject(privKey, algorithm, password.ToCharArray(), new SecureRandom());
            }
        }

        /// <summary>
        /// Save an encrypted RSA key to a PEM file
        /// </summary>
        /// <param name="rsa">Private key</param>
        /// <param name="outputFile">PEM output file</param>
        /// <param name="password">Password</param>
        /// <param name="algorithm">Algorithm</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider rsa, string outputFile, string password, string algorithm = "AES-256-CBC")
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(rsa, fs, password, algorithm);
            }
        }

        /// <summary>
        /// Save a private RSA key to a PEM file
        /// </summary>
        /// <param name="rsa">Private key</param>
        /// <param name="output">Output stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider rsa, Stream output)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (output == null)
                throw new ArgumentNullException(nameof(output));

            using (StreamWriter sw = new StreamWriter(output, Encoding.Default))
            {
                PemWriter pemWriter = new PemWriter(sw);
                AsymmetricCipherKeyPair ackp = DotNetUtilities.GetRsaKeyPair(rsa);
                RsaPrivateCrtKeyParameters privKey = (RsaPrivateCrtKeyParameters)ackp.Private;
                pemWriter.WriteObject(privKey);
            }
        }

        /// <summary>
        /// Save a private RSA key to a PEM file
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="outputFile"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SavePrivateKeyToPEM(RSACryptoServiceProvider rsa, string outputFile)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));

            using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                SavePrivateKeyToPEM(rsa, fs);
            }
        }

        #endregion

        #region Save / Load Win KeyStore

        /// <summary>
        /// Save a RSA key in the Windows KeyStore
        /// </summary>
        /// <param name="rsa">RSA key</param>
        /// <param name="containerName">Container name</param>
        /// <param name="csppf">CspProviderFlags</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void SaveInWinKeyStore(RSACryptoServiceProvider rsa, string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (containerName == null)
                throw new ArgumentNullException(nameof(containerName));

            CspParameters cp = new CspParameters();
            cp.KeyContainerName = containerName;
            cp.Flags = csppf;

            using (RSACryptoServiceProvider winKSkey = new RSACryptoServiceProvider(cp))
            {
                winKSkey.FromXmlString(rsa.ToXmlString(true));
            }
        }

        /// <summary>
        /// Load a RSA key from the Windows KeyStore 
        /// </summary>
        /// <param name="containerName">Container name</param>
        /// <param name="csppf">CspProviderFlags</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static RSACryptoServiceProvider LoadFromWinKeyStore(string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            if (containerName == null)
                throw new ArgumentNullException(nameof(containerName));

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
        /// <exception cref="ArgumentNullException"></exception>
        public static void DeleteFromWinKeyStore(string containerName, CspProviderFlags csppf = CspProviderFlags.UseMachineKeyStore)
        {
            if (containerName == null)
                throw new ArgumentNullException(nameof(containerName));

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
