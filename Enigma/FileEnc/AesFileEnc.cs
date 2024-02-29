using Enigma.IO;
using Enigma.KDF;
using Enigma.Padding;
using Enigma.Random;
using Enigma.SymKey;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Enigma.FileEnc
{
    /// <summary>
    /// Encrypt/Decrypt files with AES-256 with RSA key or password
    /// </summary>
    public static class AesFileEnc
    {
        private const byte VERSION = 0x05;
        private const int BUFFER_SIZE = 4096;
        private const string RSA_HEADER = "AENCR!";
        private const string PASS_HEADER = "AENCP!";
        private const int SALT_SIZE = 16;

        #region Encrypt with key

        /// <summary>
        /// Encrypt with AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            byte[] key = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keyData;
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryHelper.WriteLV(ms, key);
                BinaryHelper.WriteLV(ms, iv);
                keyData = ms.ToArray();
            }

            byte[] encKeyData = PubKey.RSA.Encrypt(rsa, keyData);

            BinaryHelper.Write(output, RSA_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, Encoding.ASCII.GetBytes(keyName));
            BinaryHelper.WriteLV(output, encKeyData);

            AES.EncryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Asynchronously encrypt with AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            byte[] key = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keyData;
            using (MemoryStream ms = new MemoryStream())
            {
                await BinaryHelper.WriteLVAsync(ms, key).ConfigureAwait(false);
                await BinaryHelper.WriteLVAsync(ms, iv).ConfigureAwait(false);
                keyData = ms.ToArray();
            }

            byte[] encKeyData = PubKey.RSA.Encrypt(rsa, keyData);

            await BinaryHelper.WriteAsync(output, RSA_HEADER, Encoding.ASCII).ConfigureAwait(false);
            await BinaryHelper.WriteAsync(output, VERSION).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, Encoding.ASCII.GetBytes(keyName)).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, encKeyData).ConfigureAwait(false);

            await AES.EncryptCBCAsync(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, rsa, keyName, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously encrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(string inputFile, string outputFile, RSACryptoServiceProvider rsa, string keyName, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await EncryptAsync(fsIn, fsOut, rsa, keyName, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Encrypt with password

        /// <summary>
        /// Encrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input file</param>
        /// <param name="output">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            byte[] salt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 60000);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            BinaryHelper.Write(output, PASS_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, salt);
            BinaryHelper.WriteLV(output, iv);

            AES.EncryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Asynchronously encrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input file</param>
        /// <param name="output">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            byte[] salt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 60000);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            await BinaryHelper.WriteAsync(output, PASS_HEADER, Encoding.ASCII).ConfigureAwait(false);
            await BinaryHelper.WriteAsync(output, VERSION).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, salt).ConfigureAwait(false);
            await BinaryHelper.WriteLVAsync(output, iv).ConfigureAwait(false);

            await AES.EncryptCBCAsync(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE).ConfigureAwait(false);
        }

        /// <summary>
        /// Encrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Encrypt(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously encrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task EncryptAsync(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await EncryptAsync(fsIn, fsOut, password, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Decrypt with key

        /// <summary>
        /// Decrypt with AES-256 with a RSA key
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="rsa"></param>
        /// <param name="notifyProgression"></param>
        public static void Decrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            input.Seek(RSA_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = BinaryHelper.ReadLV(input);
            byte[] encKeyData = BinaryHelper.ReadLV(input);

            if (notifyProgression != null)
                notifyProgression(RSA_HEADER.Length + 1 + 2 * sizeof(int) + keyNameData.Length + encKeyData.Length);

            byte[] keyData = PubKey.RSA.Decrypt(rsa, encKeyData);

            byte[] key, iv;
            using (MemoryStream ms = new MemoryStream(keyData))
            {
                key = BinaryHelper.ReadLV(ms);
                iv = BinaryHelper.ReadLV(ms);
            }

            AES.DecryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Asynchronously decrypt with AES-256 with a RSA key
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="rsa"></param>
        /// <param name="notifyProgression"></param>
        public static async Task DecryptAsync(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            input.Seek(RSA_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] encKeyData = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);

            if (notifyProgression != null)
                notifyProgression(RSA_HEADER.Length + 1 + 2 * sizeof(int) + keyNameData.Length + encKeyData.Length);

            byte[] keyData = PubKey.RSA.Decrypt(rsa, encKeyData);

            byte[] key, iv;
            using (MemoryStream ms = new MemoryStream(keyData))
            {
                key = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
                iv = await BinaryHelper.ReadLVAsync(ms).ConfigureAwait(false);
            }

            await AES.DecryptCBCAsync(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, rsa, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously decrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(string inputFile, string outputFile, RSACryptoServiceProvider rsa, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await DecryptAsync(fsIn, fsOut, rsa, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion

        #region Decrypt with password

        /// <summary>
        /// Decrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            input.Seek(PASS_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] salt = BinaryHelper.ReadLV(input);
            byte[] iv = BinaryHelper.ReadLV(input);

            if (notifyProgression != null)
                notifyProgression(PASS_HEADER.Length + 1 + 2 * sizeof(int) + salt.Length + iv.Length);

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 60000);

            AES.DecryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression);
        }

        /// <summary>
        /// Asynchronously decrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(Stream input, Stream output, string password, Action<int>? notifyProgression = null)
        {
            input.Seek(PASS_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] salt = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);
            byte[] iv = await BinaryHelper.ReadLVAsync(input).ConfigureAwait(false);

            if (notifyProgression != null)
                notifyProgression(PASS_HEADER.Length + 1 + 2 * sizeof(int) + salt.Length + iv.Length);

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt, 60000);

            await AES.DecryptCBCAsync(input, output, key, iv, new Pkcs7Padding(), notifyProgression).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static void Decrypt(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        /// <summary>
        /// Asynchronously decrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        public static async Task DecryptAsync(string inputFile, string outputFile, string password, Action<int>? notifyProgression = null)
        {
            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    await DecryptAsync(fsIn, fsOut, password, notifyProgression).ConfigureAwait(false);
                }
            }
        }

        #endregion
    }
}